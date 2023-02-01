/*
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

package com.snc.discovery.integration;

import org.testcontainers.containers.BindMode;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.MountableFile;

import java.nio.file.Path;

public class VaultAgentContainer extends GenericContainer<VaultAgentContainer> {
    private static final String agentConfigFile = "/vault/config/agent.hcl";
    private static final Integer httpPort = 8300;
    private static final Integer httpsPort = 8301;

    public VaultAgentContainer(String image, Network network, Path roleId, Path secretId, Path cert, Path key) {
        super(image);
        this.withExposedPorts(httpPort, httpsPort)
            .withNetwork(network)
            .withClasspathResourceMapping("/agent.hcl", agentConfigFile, BindMode.READ_ONLY)
            .withCopyFileToContainer(MountableFile.forHostPath(roleId), "/vault/config/roleID")
            .withCopyFileToContainer(MountableFile.forHostPath(secretId), "/vault/config/secretID")
            .withCopyFileToContainer(MountableFile.forHostPath(cert), "/vault/config/vault-agent.pem")
            .withCopyFileToContainer(MountableFile.forHostPath(key), "/vault/config/vault-agent-key.pem")
            .withCommand("vault agent -config=" + agentConfigFile)
            .waitingFor(Wait.forLogMessage(".*authentication successful.*", 1));
    }

    public String getAddress() {
        return String.format("http://%s:%d", getHost(), getMappedPort(httpPort));
    }

    public String getTLSAddress() {
        return String.format("https://%s:%d", getHost(), getMappedPort(httpsPort));
    }
}
