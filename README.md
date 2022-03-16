# LdapUserProviderBundle

This bundle provides LDAP authentication. It can also be used for authorization by retrieving the groups to which users belong and setting them as roles.
It relies on the standard ldap php extension.

## Dependencies
    - it should be compliant with Symfony 3.4 and 4.4
    - ext-ldap
    - symfony/ldap

### Get the Bundle with composer
``` shell
composer require wiser/ldap-user-provider-bundle
```

### Configure services.yaml
``` yaml
# config/services.yaml
parameters:
    ldap.host: 'dc.company.com'
    ldap.port: '389'
    ldap.user: 'user'               # administrative account used to bind user/password
    ldap.password: 'password'
    ldap.base_dn: 'dc=COMPANY,dc=ORG'
    ldap.roles_ou_filter: 'OU=APPLICATIONS,OU=GROUPS'

services:
    Symfony\Component\Ldap\Adapter\ExtLdap\Adapter:
        arguments:
            -   host: '%ldap.host%'
                port: '%ldap.port%'

    Symfony\Component\Ldap\Ldap:
        arguments: ['@Symfony\Component\Ldap\Adapter\ExtLdap\Adapter']
```

### Configure security.yaml

``` yaml
# config/packages/security.yaml

security:
    providers:
        my_ldap:
            wiser_ldap: # this is the configuration key that matches this bundle
                service: Symfony\Component\Ldap\Ldap
                base_dn: '%ldap.base_dn%'
                search_dn: '%ldap.user%'
                search_password: '%ldap.password%'
                roles_ou_filter: '%ldap.roles_ou_filter%'
# there are other configuration settings, check the code (LdapUserProviderFactory.php) to find them by yourself ;)

    firewalls:
        restricted_area:
            anonymous: true
            form_login_ldap: ldap
                login_path: login
                    check_path: login
                    csrf_token_generator: security.csrf.token_manager
                    service: Symfony\Component\Ldap\Ldap
                    dn_string: '%ldap.base_dn%'
                    search_dn: '%ldap.user%'
                    search_password: '%ldap.password%'
                    query_string: (&(ObjectClass=Person)(sAMAccountName={username}))
                    provider: my_ldap
```

**Note:**
> You can refer to the official Symfony documentation :
> https://symfony.com/doc/current/security/ldap.html
