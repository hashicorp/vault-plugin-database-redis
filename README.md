# vault-plugin-database-redis

This is a standalone [Database Plugin](https://www.vaultproject.io/docs/secrets/databases) for use with [Hashicorp
Vault](https://www.github.com/hashicorp/vault).

This plugin supports the generation of static and dynamic user roles and root credential rotation on a standalone Redis server.

## Quick Links

- [Vault Website](https://www.vaultproject.io)
- [Plugin System](https://www.vaultproject.io/docs/plugins)


## Getting Started

This is a [Vault plugin](https://www.vaultproject.io/docs/plugins)
and is meant to work with Vault. This guide assumes you have already installed
Vault and have a basic understanding of how Vault works.

Otherwise, first read this guide on how to [get started with
Vault](https://www.vaultproject.io/intro/getting-started/install.html).

## Development

If you wish to work on this plugin, you'll first need
[Go](https://www.golang.org) installed on your machine (version 1.17+ recommended)

Make sure Go is properly installed, including setting up a [GOPATH](https://golang.org/doc/code.html#GOPATH).

More details in the [Environment Set Up](#environment-set-up) section.

## Build

To compile a development version of this plugin, run `make` or `make dev`.
This will put the plugin binary in the `bin` and `$GOPATH/bin` folders. `dev`
mode will only generate the binary for your platform and is faster:

```sh
$ make dev
```

## Installation

The Vault plugin system is documented on the [Vault documentation site](https://www.vaultproject.io/docs/internals/plugins.html).

You will need to define a plugin directory using the `plugin_directory` configuration directive, then place the
`vault-plugin-database-redis` executable generated above, into the directory.

**Please note:** This plugin is incompatible with Vault versions before 1.6.0 due to an update of the database plugin interface. You will be able to register the plugin in the plugins catalog with an older version of Vault but when you try to initialize the plugin to connect to a database instance you will get this error.
````bash
Error writing data to database/config/my-redis: Error making API request.

URL: PUT http://127.0.0.1:8200/v1/database/config/my-redis
Code: 400. Errors:

* error creating database object: Incompatible API version with plugin. Plugin version: 5, Client versions: [3 4]
````

## Tests

### Environment Set Up

To test `go test` will execute a set of basic tests against the `docker.io/redis:latest` Redis database image. To test against different Redis images, for example 5.0-buster, set the `REDIS_VERSION=5.0-buster` environment variable. If you want to run the tests against a local Redis installation or an already running Redis container, set the environment variables `REDIS_HOST` before executing, as well as `REDIS_TLS`, `CA_CERT_FILE` for acceptance tests.

**Note:** The tests assume that the Redis database instance has a default user with the following ACL settings user default on `nopass ~* +@all`. If not you will need to align the Administrator username and password with the pre-set values in the [redis_test.go](https://github.com/hashicorp/vault-plugin-database-redis/blob/main/redis_test.go) file.

Set `VAULT_ACC` to execute all of the tests. A subset of tests can be run using the command `go test -run TestDriver/Init` for example.

A Terraform project is included for convenience to initialize a new docker container and generate certificates if needed.
If not already available, you can install Terraform by using [this documentation](https://docs.aws.amazon.com/cli/latest/userguide/cli-configure-files.html).

The setup script tries to find and use available Redis credentials from the environment. You can configure Redis credentials by using or editing the provider defined `./bootstrap/terraform/redis.tf` with your desired set of credentials.

To set up the test container:

```sh
$ make setup-env
...
Apply complete! Resources: 1 added, 0 changed, 0 destroyed.

$ source ./bootstrap/terraform/local_environment_setup.sh

$ make configure
```

### Environment Teardown

The test container created via the setup-env command can be destroyed using the teardown-env command.

```sh
$ make teardown-env
...
Destroy complete! Resources: 1 destroyed.
```

### Testing Manually

Put the plugin binary into a location of your choice. This directory
will be specified as the [`plugin_directory`](https://www.vaultproject.io/docs/configuration#plugin_directory)
in the Vault config used to start the server.

```hcl
# config.hcl
plugin_directory = "path/to/plugin/directory"
...
```

Start a Vault server with this config file:

```sh
$ vault server -dev -config=path/to/config.hcl ...
...
```

Once the server is started, register and start the plugin in the Vault server's [plugin catalog](https://www.vaultproject.io/docs/plugins/plugin-architecture#plugin-catalog):

```sh
$ SHA256=$(shasum -a 256 plugins/redis-database-plugin | cut -d' ' -f1)

$ vault write sys/plugins/catalog/database/redis-database-plugin sha256=$SHA256 \
        command=redis-database-plugin
```

Enable the database engine to use this plugin:
```sh
$ vault secrets enable database
```

At this stage you are now ready to initialize the plugin to connect to the Redis DB using unencrypted or encrypted communications.

Prior to initializing the plugin, ensure that you have created an administration account. Vault will use the user specified here to create/update/revoke database credentials. That user must have the appropriate rule `+@admin` to perform actions upon other database users.

Export the certificate:
```sh
$ CACERT=$(cat /path/to/cacert)
```

```sh
$ vault write database/config/my-redis plugin_name="redis-database-plugin" \
        host="localhost" port=6379 username="Administrator" password="password" \
        allowed_roles="my-redis-*-role" tls=true insecure_tls=true ca_cert="$CACERT"

# You should consider rotating the admin password. Note that if you do, the new password will never be made available
# through Vault, so you should create a vault-specific database admin user for this.
$ vault write -force database/rotate-root/my-redis
 ```

### Dynamic Role Creation

When you create roles, you need to provide a JSON string containing the Redis ACL rules which are documented [here](https://redis.io/commands/acl-cat) or in the output of the `ACL CAT` redis command.

```sh
# if a creation_statement is not provided the user account will default to a read only user, '["~*", "+@read"]' that can read any key.
$ vault write database/roles/my-redis-admin-role db_name=my-redis \
        default_ttl="5m" max_ttl="1h" creation_statements='["+@admin"]'

$ vault write database/roles/my-redis-read-foo-role db_name=my-redis \
        default_ttl="5m" max_ttl="1h" creation_statements='["~foo", "+@read"]'
Success! Data written to: database/roles/my-redis-read-foo-role
```

To retrieve the credentials for the dynamic accounts

```sh

$vault read database/creds/my-redis-admin-role
Key                Value
---                -----
lease_id           database/creds/my-redis-admin-role/OxCTXJcxQ2F4lReWPjbezSnA
lease_duration     5m
lease_renewable    true
password           dACqHsav6-attdv1glGZ
username           V_TOKEN_MY-REDIS-ADMIN-ROLE_YASUQUF3GVVD0ZWTEMK4_1608481717

$ vault read database/creds/my-redis-read-foo-role
Key                Value
---                -----
lease_id           database/creds/my-redis-read-foo-role/Yn99BrX4t0NkLyifm4NmsEUB
lease_duration     5m
lease_renewable    true
password           ZN6gdTKszk7oc9Oztc-o
username           V_TOKEN_MY-REDIS-READ-FOO-ROLE_PUAINND1FC5XQGRC0HIF_1608481734

```

### Static Role Creation

In order to use static roles, the user must already exist in the Redis ACL list. The example below assumes that there is an existing user with the name "vault-edu". If the user does not exist you will receive the following error.

```sh
Error writing data to database/static-roles/static-account: Error making API request.

URL: PUT http://127.0.0.1:8200/v1/database/static-roles/static-account
Code: 400. Errors:

* cannot update static account username

```

```sh
$ vault write database/static-roles/static-account db_name=insecure-redis \
        username="vault-edu" rotation_period="5m"
Success! Data written to: database/static-roles/static-account
````

To retrieve the credentials for the vault-edu user

```sh
$ vault read database/static-creds/static-account
Key                    Value
---                    -----
last_vault_rotation    2020-12-20T10:39:49.647822-06:00
password               ylKNgqa3NPVAioBf-0S5
rotation_period        5m
ttl                    3m59s
username               vault-edu
```

### Automated Tests

To run the tests:

```sh
$ make test
```

You can also specify a `TESTARGS` variable to filter tests like so:

```sh
$ make test TESTARGS='-run=TestInit'
```

### Acceptance Tests

The majority of tests must communicate with an existing Redis instance. See the [Environment Set Up](#environment-set-up) section for instructions on how to prepare a Redis container.

Some environment variables are required to run tests expecting to communicate with a Redis container.

```sh
$ export TEST_REDIS_HOST=localhost &&\
$ export TEST_REDIS_PORT=6379 &&\
$ export TEST_REDIS_USERNAME=default &&\
$ export TEST_REDIS_PASSWORD=the-strong-one &&\
$ export TEST_REDIS_CACERT_RELATIVE_PATH=/scripts/tests/tls/ca.crt

$ make test
```

## Spring Cloud Vault Integration

> Tested on [spring-cloud-vault:3.1.0](https://docs.spring.io/spring-cloud-vault/docs/3.1.0/reference/html)

In order to enable integration with `Spring Cloud Vault` and therefore supply dynamically-generated Redis credentials to Spring applications, we can use `org.springframework.cloud:spring-cloud-vault-config-databases` with [Multiple Databases](https://docs.spring.io/spring-cloud-vault/docs/3.1.0/reference/html/#vault.config.backends.databases) configuration approach.

Sample `application.yml` configuration (not-related sections are omitted):

```yaml
spring:
  cloud:
    vault:
      host: 127.0.0.1
      port: 8200
      authentication: TOKEN
      token: ${VAULT_TOKEN}
      databases:
        redis:
          enabled: true
          role: my-redis-role
          backend: database
          username-property: spring.redis.username
          password-property: spring.redis.password
  config:
    import: vault://
```

**Please note:** Spring Cloud Vault does not support `max_ttl` yet, thus we have to set it up to `0` when creating configurations. More details can be found [here](https://docs.spring.io/spring-cloud-vault/docs/3.1.0/reference/html/#vault.config.backends.databases).

