package com.snc.discovery.integration;

import org.testcontainers.containers.BindMode;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.MountableFile;

import java.nio.file.Path;

public class VaultAgentContainer extends GenericContainer<VaultAgentContainer> {
    private static final String agentConfigFile = "/vault/config/agent.hcl";

    public VaultAgentContainer(String image, Network network, Path roleId, Path secretId) {
        super(image);
        this.withExposedPorts(8300)
            .withNetwork(network)
            .withClasspathResourceMapping("/agent.hcl", agentConfigFile, BindMode.READ_ONLY)
            .withCopyFileToContainer(MountableFile.forHostPath(roleId), "/vault/config/roleID")
            .withCopyFileToContainer(MountableFile.forHostPath(secretId), "/vault/config/secretID")
            .withCommand("vault agent -config=" + agentConfigFile)
            .waitingFor(Wait.forLogMessage(".*authentication successful.*", 1));
    }

    public String getAddress() {
        return String.format("http://%s:%d", getHost(), getFirstMappedPort());
    }
}
