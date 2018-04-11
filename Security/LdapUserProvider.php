<?php

namespace Wiser\LdapUserProviderBundle\Security;

use Symfony\Component\Ldap\Entry;
use Symfony\Component\Security\Core\Exception\InvalidArgumentException;
use Symfony\Component\Security\Core\Exception\UnsupportedUserException;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Core\User\User;
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
     * @param string        $searchDn
     * @param string        $searchPassword
     * @param string        $uidKey
     * @param string        $filter
     * @param string        $rolesOuFilter
     * @param string        $rolesUserAttribute
     * @param string        $rolesFilter
     */
    public function __construct(LdapInterface $ldapConnection, $baseDn, $searchDn = null, $searchPassword = null, $uidKey = 'sAMAccountName', $filter = '({uid_key}={username})', $rolesOuFilter = '', $rolesUserAttribute = 'member', $rolesFilter = '(objectClass=group)')
    {
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
     * {@inheritdoc}
     */
    public function loadUserByUsername($username)
    {
        try {
            $this->ldapConnection->bind($this->searchDn, $this->searchPassword);
            $username = $this->ldapConnection->escape($username, '', LdapInterface::ESCAPE_FILTER);
            $query = str_replace('{username}', $username, $this->defaultSearch);
            $search = $this->ldapConnection->query($this->baseDn, $query);
        } catch (ConnectionException $e) {
            throw new UsernameNotFoundException(sprintf('User "%s" not found.', $username), 0, $e);
        }

        $entries = $search->execute();
        $count = count($entries);

        if (!$count) {
            throw new UsernameNotFoundException(sprintf('User "%s" not found.', $username));
        }

        if ($count > 1) {
            throw new UsernameNotFoundException('More than one user found');
        }

        $entry = $entries[0];

        try {
            if (null !== $this->uidKey) {
                $username = $this->getAttributeValue($entry, $this->uidKey);
            }
        } catch (InvalidArgumentException $e) {
        }

        return $this->loadUser($username, $entry);
    }

    /**
     * {@inheritdoc}
     */
    public function refreshUser(UserInterface $user)
    {
        if (!$user instanceof User) {
            throw new UnsupportedUserException(sprintf('Instances of "%s" are not supported.', get_class($user)));
        }
        $password = null;

        return new User($user->getUsername(), $password, $user->getRoles());
    }

    /**
     * {@inheritdoc}
     */
    public function supportsClass($class)
    {
        return 'Symfony\Component\Security\Core\User\User' === $class;
    }

    /**
     * Loads a user from an LDAP entry.
     *
     * @param string $username
     * @param Entry  $entry
     *
     * @return User
     */
    protected function loadUser($username, Entry $entry)
    {
        $roles = $this->getLdapRoles($entry);
        $password = null;

        return new User($username, $password, $roles);
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
    {
        $rolesBaseDn = $this->rolesOuFilter . ',' . $this->baseDn;
        $rolesFilter = sprintf('(&%s(member=%s))', $this->rolesFilter, $entry->getDn());
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
