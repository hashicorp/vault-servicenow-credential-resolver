# vault-servicenow-credential-resolver

----

**Please note**: We take Vault's security and our users' trust very seriously.
If you believe you have found a security issue in Vault or
vault-servicenow-credential-resolver, _please responsibly disclose_ by contacting
us at [security@hashicorp.com](mailto:security@hashicorp.com).

----

This repository contains the source code for HashiCorp's Vault credential resolver.
It allows ServiceNow [MID servers] to use Vault for [external credential storage].

## Getting started

See the user documentation at [vaultproject.io] for installation and configuration
instructions.

## Building from source

To build from source locally, you will need to pull in some dependencies this project
has on MID server libraries. You can use the excellent Docker images built by
[bmoers/docker-mid-server] to do this:

```bash
id="$(docker create moers/mid-server:quebec)"
docker cp $id:/opt/agent/lib/mid.jar lib/
docker cp $id:/opt/agent/lib/commons-glide.jar lib/
docker rm -v $id
```

Once `lib/` is populated, you can create a JAR file ready to upload to your MID
server by running the `jar` Gradle task:

```bash
./gradlew jar
```

You can find the built JAR at `build/libs/vault-servicenow-credential-resolver.jar`.

## Running tests

If you haven't already, you'll need to manually pull in `mid.jar` and
`commons-glide.jar` as detailed above.

```bash
# Unit tests
./gradlew test

# Integration tests - depends on docker
./gradlew integrationTest
```

[MID servers]: https://docs.servicenow.com/bundle/quebec-servicenow-platform/page/product/mid-server/concept/mid-server-landing.html
[external credential storage]: https://docs.servicenow.com/bundle/quebec-servicenow-platform/page/product/credentials/concept/c_ExternalCredentialStorage.html
[vaultproject.io]: https://vaultproject.io/docs/platform/servicenow
[bmoers/docker-mid-server]: https://github.com/bmoers/docker-mid-server
