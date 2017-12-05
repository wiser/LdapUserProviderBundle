<?php

namespace Wiser\LdapUserProviderBundle;

use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Bundle\Bundle;
use Wiser\LdapUserProviderBundle\Security\LdapUserProviderFactory;

class WiserLdapUserProviderBundle extends Bundle
{
    public function build(ContainerBuilder $container)
    {
        $extension = $container->getExtension('security');
        $extension->addUserProviderFactory(new LdapUserProviderFactory);
    }
}
