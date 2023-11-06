<?php

namespace Wiser\LdapUserProviderBundle\Security;

use Symfony\Component\Ldap\Entry;
use Symfony\Component\Security\Core\Exception\InvalidArgumentException;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Exception\UserNotFoundException;
use Symfony\Component\Ldap\Security\LdapUser;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Core\User\UserProviderInterface;
use Symfony\Component\Ldap\Exception\ConnectionException;
use Symfony\Component\Ldap\LdapInterface;

/**
 * LdapUserProvider is a simple Ldap user provider with groups as roles feature.
 */
class LdapUserProvider implements UserProviderInterface
{
    private $ldapConnection;
    private $baseDn;
    private $searchDn;
    private $searchPassword;
    private $uidKey;
    private $defaultSearch;
    private $rolesOuFilter;
    private $rolesUserAttribute;
    private $rolesFilter;

    /**
     * @param LdapInterface $ldapConnection
     * @param string        $baseDn
     * @param string|null   $searchDn
     * @param string|null   $searchPassword
     * @param string|null   $uidKey
     * @param string|null   $filter
     * @param string|null   $rolesOuFilter
     * @param string|null   $rolesUserAttribute
     * @param string|null   $rolesFilter
     */
    public function __construct(
        LdapInterface $ldapConnection,
        $baseDn,
        $searchDn = null,
        $searchPassword = null,
        $uidKey = 'sAMAccountName',
        $filter = '({uid_key}={username})',
        $rolesOuFilter = '',
        $rolesUserAttribute = 'member',
        $rolesFilter = '(objectClass=group)'
    ) {
        $this->ldapConnection = $ldapConnection;
        $this->baseDn = $baseDn;
        $this->searchDn = $searchDn;
        $this->searchPassword = $searchPassword;
        $this->uidKey = $uidKey;
        $this->defaultSearch = str_replace('{uid_key}', $uidKey, $filter);
        $this->rolesOuFilter = $rolesOuFilter;
        $this->rolesUserAttribute = $rolesUserAttribute;
        $this->rolesFilter = $rolesFilter;
    }

    /**
     * @inheritDoc
     */
    public function loadUserByUsername($username)
    {
        return $this->loadUserByIdentifier($username);
    }

    /**
     * {@inheritdoc}
     */
    public function loadUserByIdentifier($identifier)
    {
        try {
            $this->ldapConnection->bind($this->searchDn, $this->searchPassword);
            $identifier = $this->ldapConnection->escape($identifier, '', LdapInterface::ESCAPE_FILTER);
            $query = str_replace('{username}', $identifier, $this->defaultSearch);
            $search = $this->ldapConnection->query($this->baseDn, $query);
        } catch (ConnectionException $e) {
            throw new UserNotFoundException(sprintf('User "%s" not found.', $identifier), 0, $e);
        }

        $entries = $search->execute();
        $count = count($entries);

        if (!$count) {
            throw new UserNotFoundException(sprintf('User "%s" not found.', $identifier));
        }

        if ($count > 1) {
            throw new UserNotFoundException('More than one user found');
        }

        $entry = $entries[0];

        try {
            if (null !== $this->uidKey) {
                $identifier = $this->getAttributeValue($entry, $this->uidKey);
            }
        } catch (InvalidArgumentException $e) {
        }

        return $this->loadUser($identifier, $entry);
    }

    /**
     * {@inheritdoc}
     */
    public function refreshUser(UserInterface $user)
    {
        if (!$user instanceof LdapUser) {
            throw new UnsupportedUserException(sprintf('Instances of "%s" are not supported.', get_class($user)));
        }
        $password = null;

        return new LdapUser($user->getEntry(), $user->getUserIdentifier(), $password, $user->getRoles());
    }

    /**
     * {@inheritdoc}
     */
    public function supportsClass($class)
    : bool {
        return LdapUser::class === $class || is_subclass_of($class, LdapUser::class);
    }

    /**
     * Loads a user from an LDAP entry.
     *
     * @param string $userIdentifier
     * @param Entry  $entry
     *
     * @return LdapUser
     */
    protected function loadUser($userIdentifier, Entry $entry)
    : LdapUser {
        $roles = $this->getLdapRoles($entry);
        $password = null;

        return new LdapUser($entry, strtolower($userIdentifier), $password, $roles);
    }

    /**
     * Fetches a required unique attribute value from an LDAP entry.
     *
     * @param null|Entry $entry
     * @param string     $attribute
     *
     * @return string
     */
    private function getAttributeValue(Entry $entry, $attribute)
    {
        if (!$entry->hasAttribute($attribute)) {
            throw new InvalidArgumentException(sprintf('Missing attribute "%s" for user "%s".', $attribute, $entry->getDn()));
        }

        $values = $entry->getAttribute($attribute);

        if (1 !== count($values)) {
            throw new InvalidArgumentException(sprintf('Attribute "%s" has multiple values.', $attribute));
        }

        return $values[0];
    }

    /**
     * Retrieve the user's roles from membership in LDAP groups
     *
     * @param Entry $entry
     *
     * @return array
     */
    private function getLdapRoles(Entry $entry)
    : array {
        $rolesBaseDn = empty($this->rolesOuFilter) ? $this->baseDn : $this->rolesOuFilter . ',' . $this->baseDn;
	    $rolesFilter = sprintf('(&%s(%s=%s))', $this->rolesFilter, $this->rolesUserAttribute, $entry->getDn());
        $search = $this->ldapConnection->query($rolesBaseDn, $rolesFilter, ['filter' => ['cn']]);
        $entries = $search->execute();

        if (count($entries) > 0) {
            return array_map(
                function ($entry) {
                    return sprintf(
                        '%s_%s',
                        'ROLE',
                        strtoupper(str_replace('-', '_', $this->getAttributeValue($entry, 'cn')))
                    );
                },
                $entries->toArray()
            );
        }

        return [];
    }
}
