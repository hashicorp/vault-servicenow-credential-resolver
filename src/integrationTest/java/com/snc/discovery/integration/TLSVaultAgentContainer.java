package com.snc.discovery.integration;

import com.github.dockerjava.api.model.Mount;
import org.testcontainers.containers.BindMode;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.Network;
import org.testcontainers.containers.wait.strategy.Wait;
import org.testcontainers.utility.MountableFile;

import java.nio.file.Path;

public class TLSVaultAgentContainer extends GenericContainer<TLSVaultAgentContainer> {
    private static final String agentConfigFile = "/vault/config/agent-tls.hcl";
    private static final String agentCertFile = "/vault/config/vault-agent.pem";
    private static final String agentKeyFile = "/vault/config/vault-agent-key.pem";

    public TLSVaultAgentContainer(String image, Network network, Path roleId, Path secretId, Path cert, Path key) {
        super(image);
        this.withExposedPorts(8300)
            .withNetwork(network)
            .withClasspathResourceMapping("/agent-tls.hcl", agentConfigFile, BindMode.READ_ONLY)
            .withCopyFileToContainer(MountableFile.forHostPath(roleId), "/vault/config/roleID")
            .withCopyFileToContainer(MountableFile.forHostPath(secretId), "/vault/config/secretID")
            .withCopyFileToContainer(MountableFile.forHostPath(cert), agentCertFile)
            .withCopyFileToContainer(MountableFile.forHostPath(key), agentKeyFile)
            .withCommand("vault agent -config=" + agentConfigFile)
            .waitingFor(Wait.forLogMessage(".*authentication successful.*", 1));
    }

    public String getAddress() {
        return String.format("https://%s:%d", getHost(), getFirstMappedPort());
    }
}
