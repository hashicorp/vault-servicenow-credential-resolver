# Copyright IBM Corp. 2021, 2026
# SPDX-License-Identifier: MPL-2.0

path "secret/*" {
    capabilities = [ "read", "update", "create" ]
}

path "ssh/issue/*" {
    capabilities = [ "update", "create" ]
}
