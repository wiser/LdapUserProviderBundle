<?php

namespace Wiser\LdapUserProviderBundle\Security;

use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\UserProvider\UserProviderFactoryInterface;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Component\DependencyInjection\ChildDefinition;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

class LdapUserProviderFactory implements UserProviderFactoryInterface
{
    public function create(ContainerBuilder $container, $id, $config): void
    {
        $container
            ->setDefinition($id, new ChildDefinition('wiser.security.user.provider.ldap'))
            ->replaceArgument(0, new Reference($config['service']))
            ->replaceArgument(1, $config['base_dn'])
            ->replaceArgument(2, $config['search_dn'])
            ->replaceArgument(3, $config['search_password'])
            ->replaceArgument(4, $config['uid_key'])
            ->replaceArgument(5, $config['filter'])
            ->replaceArgument(6, $config['roles_ou_filter'])
            ->replaceArgument(7, $config['roles_user_attribute']);
        ;
    }

    public function getKey(): string
    {
        return 'wiser_ldap';
    }

    public function addConfiguration(NodeDefinition $node): void
    {
        $node
            ->children()
                ->scalarNode('service')->isRequired()->cannotBeEmpty()->defaultValue('Symfony\Component\Ldap\Ldap')->end()
                ->scalarNode('base_dn')->isRequired()->cannotBeEmpty()->end()
                ->scalarNode('search_dn')->end()
                ->scalarNode('search_password')->end()
                ->scalarNode('uid_key')->defaultValue('sAMAccountName')->end()
                ->scalarNode('filter')->defaultValue('({uid_key}={username})')->end()
                ->scalarNode('roles_ou_filter')->defaultNull()->end()
                ->scalarNode('roles_user_attribute')->defaultValue('member')->end()
            ->end()
        ;
    }
}
