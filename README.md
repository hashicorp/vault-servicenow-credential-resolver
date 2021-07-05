# vault-servicenow-credential-resolver

----

**Please note**: We take Vault's security and our users' trust very seriously. If you believe you have found a security issue in Vault or vault-servicenow-credential-resolver, _please responsibly disclose_ by contacting us at [security@hashicorp.com](mailto:security@hashicorp.com).

----

This repository contains the source code for HashiCorp's Vault ServiceNow external
credential resolver. The integration allows MID servers to use Vault as storage
for credentials.

## Running tests

```bash
# Unit tests
./gradlew test

# Integration tests - depends on docker
./gradlew integrationTest
```
