# Copyright (c) HashiCorp, Inc.
# SPDX-License-Identifier: MPL-2.0

path "secret/*" {
    capabilities = [ "read", "update", "create" ]
}

path "ssh/issue/*" {
    capabilities = [ "update", "create" ]
}
