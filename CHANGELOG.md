## 0.3.0 (September 8, 2026)

Features:

* Issues dynamic SSH certificates for the configured user instead of the Vault role's `default_user`. [GH-43](https://github.com/hashicorp/vault-servicenow-credential-resolver/pull/43)
* Add support for bearer token and SSH certificates as credential types [GH-38](https://github.com/hashicorp/vault-servicenow-credential-resolver/pull/38)
* Add support for the snmpv3 `contextname` field [GH-33](https://github.com/hashicorp/vault-servicenow-credential-resolver/pull/33)

Dependency Updates:

* Bump `com.google.code.gson:gson` from 2.8.8 to 2.14.0 (fixes CVE-2022-25647) [GH-44](https://github.com/hashicorp/vault-servicenow-credential-resolver/pull/44)
* Bump test-scope dependencies with 3 updates [GH-44](https://github.com/hashicorp/vault-servicenow-credential-resolver/pull/44)
  * Updates `com.github.tomakehurst:wiremock-jre8` from 2.31.0 to 2.35.2
  * Updates `com.squareup.okhttp3:okhttp-bom` from 4.9.1 to 4.12.0
  * Updates `commons-io:commons-io` from 2.11.0 to 2.20.0
* Constrain test-scope transitive dependencies to patched versions [GH-44](https://github.com/hashicorp/vault-servicenow-credential-resolver/pull/44)
  * Updates `org.eclipse.jetty` modules from 9.4.43.v20210629 to 9.4.58.v20250814
  * Updates `com.fasterxml.jackson.core` modules from 2.12.5 to 2.22.2
  * Updates `com.google.guava:guava` from 30.1.1-jre to 33.7.1-jre
  * Updates `commons-fileupload:commons-fileupload` from 1.4 to 1.6.0
  * Updates `org.apache.commons:commons-lang3` from 3.12.0 to 3.20.0
  * Updates `net.minidev:json-smart` from 2.4.7 to 2.6.0
  * Updates `com.jayway.jsonpath:json-path` from 2.6.0 to 2.9.0
  * Updates `com.github.jknack:handlebars` from 4.2.0 to 4.5.4
  * Updates `org.xmlunit:xmlunit-core` from 2.8.2 to 2.13.0

## 0.2.0 (November 15, 2023)

Features:

* Add support for SNMP v3 [GH-22](https://github.com/hashicorp/vault-servicenow-credential-resolver/pull/22)

## 0.1.0 (July 28, 2021)

Features:

* Initial release
