/*
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

package com.snc.discovery.integration;

import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;

public class VaultContainer extends GenericContainer<VaultContainer> {
    public VaultContainer(String image, Network network) {
        super(image);
        this.withExposedPorts(8200)
            .withNetwork(network)
            .withNetworkAliases("vault")
            .withEnv("VAULT_DEV_ROOT_TOKEN_ID", "root");
    }

    public String getAddress() {
        return String.format("http://%s:%d", getHost(), getFirstMappedPort());
    }
}
