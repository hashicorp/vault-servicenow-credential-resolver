package com.snc.discovery.integration;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.snc.discovery.CredentialResolver;
import okhttp3.tls.HeldCertificate;
import org.apache.http.client.HttpResponseException;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPut;
import org.apache.http.entity.StringEntity;
import org.junit.BeforeClass;
import org.junit.ClassRule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;
import org.testcontainers.containers.Network;
import org.testcontainers.shaded.org.apache.commons.io.FileUtils;

import javax.net.ssl.SSLHandshakeException;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.nio.charset.Charset;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;
import java.util.regex.Pattern;

import static org.junit.Assert.*;

public class CredentialResolverTest {
    private static final String VAULT_IMAGE = "hashicorp/vault:1.7.3";
    private static final Gson gson = new Gson();
    private static final Network network = Network.newNetwork();

    @ClassRule
    public static final VaultContainer vault = new VaultContainer(VAULT_IMAGE, network);
    @ClassRule
    public static VaultAgentContainer agent;
    @ClassRule
    public static final TemporaryFolder tempFolder = new TemporaryFolder();

    private static String certPem;

    @BeforeClass
    public static void setupClass() throws IOException {
        // Create secret material
        put("secret/data/ssh", "{\"data\":{\"username\":\"ssh-user\",\"private_key\":\"foo\"}}");

        // Create policy
        JsonObject policyJson = new JsonObject();
        policyJson.addProperty("policy", readResource("policy.hcl"));
        put("sys/policies/acl/all-kv", gson.toJson(policyJson));

        // Setup approle auth for vault agent to use
        put("sys/auth/approle", "{\"type\":\"approle\"}");
        put("auth/approle/role/role1", "{\"bind_secret_id\":\"true\",\"token_policies\":\"all-kv\"}");

        // Fetch approle login details
        JsonObject response = get("auth/approle/role/role1/role-id");
        String roleId = response.getAsJsonObject("data").get("role_id").getAsString();
        response = put("auth/approle/role/role1/secret-id", null);
        String secretId = response.getAsJsonObject("data").get("secret_id").getAsString();

        // Write approle login details to files
        tempFolder.create();
        File roleIdFile = tempFolder.newFile("role_id");
        File secretIdFile = tempFolder.newFile("secret_id");
        FileUtils.writeStringToFile(roleIdFile, roleId, Charset.defaultCharset());
        FileUtils.writeStringToFile(secretIdFile, secretId, "UTF-8");

        // Generate agent key material
        String localhost = InetAddress.getByName("localhost").getCanonicalHostName();
        HeldCertificate localhostCertificate = new HeldCertificate.Builder()
            .addSubjectAlternativeName(localhost)
            .build();
        certPem = localhostCertificate.certificatePem();
        String keyPem = localhostCertificate.privateKeyPkcs8Pem();
        File certFile = tempFolder.newFile("agent-cert.pem");
        File keyFile = tempFolder.newFile("agent-key.pem");
        FileUtils.writeStringToFile(certFile, certPem, Charset.defaultCharset());
        FileUtils.writeStringToFile(keyFile, keyPem, Charset.defaultCharset());

        // Start vault agent, and mount in approle login details
        agent = new VaultAgentContainer(
            VAULT_IMAGE, network,
            roleIdFile.toPath(), secretIdFile.toPath(),
            certFile.toPath(), keyFile.toPath());
        agent.start();
    }

    @Test
    public void testHappyPath() throws IOException {
        CredentialResolver cr = new CredentialResolver(properties(agent.getAddress(), null, null)::get);
        HashMap<String, String> input = new HashMap<>();
        input.put(CredentialResolver.ARG_ID, "secret/data/ssh");
        input.put(CredentialResolver.ARG_TYPE, "ssh_private_key");
        Map result = cr.resolve(input);
        assertEquals("ssh-user", result.get(CredentialResolver.VAL_USER));
        assertEquals("foo", result.get(CredentialResolver.VAL_PKEY));
    }

    @Test
    public void testQueryVaultDirectlyFails() {
        CredentialResolver cr = new CredentialResolver(properties(vault.getAddress(), null, null)::get);
        HashMap<String, String> input = new HashMap<>();
        input.put(CredentialResolver.ARG_ID, "secret/data/ssh");
        HttpResponseException e = assertThrows(HttpResponseException.class, () -> cr.resolve(input));
        assertErrorContains(e, "400.*errors.*missing client token");
    }

    @Test
    public void test404() {
        CredentialResolver cr = new CredentialResolver(properties(agent.getAddress(), null, null)::get);
        HashMap<String, String> input = new HashMap<>();
        input.put(CredentialResolver.ARG_ID, "secret/data/not-there");
        HttpResponseException e = assertThrows(HttpResponseException.class, () -> cr.resolve(input));
        assertErrorContains(e, "404");
    }

    @Test
    public void testBadSecretPath() {
        CredentialResolver cr = new CredentialResolver(properties(agent.getAddress(), null, null)::get);
        HashMap<String, String> input = new HashMap<>();
        input.put(CredentialResolver.ARG_ID, "secret/bad-path");
        HttpResponseException e = assertThrows(HttpResponseException.class, () -> cr.resolve(input));
        assertErrorContains(e, "404.*warnings.*invalid path");
    }

    @Test
    public void testDefaultTLS() {
        CredentialResolver cr = new CredentialResolver(properties(agent.getTLSAddress(), null, null)::get);
        HashMap<String, String> input = new HashMap<>();
        input.put(CredentialResolver.ARG_ID, "secret/data/ssh");
        SSLHandshakeException e = assertThrows(SSLHandshakeException.class, () -> cr.resolve(input));
        assertErrorContains(e, ".*unable to find valid certification path to requested target");
    }

    @Test
    public void testSkipTLS() throws IOException {
        CredentialResolver cr = new CredentialResolver(properties(agent.getTLSAddress(), null, true)::get);
        HashMap<String, String> input = new HashMap<>();
        input.put(CredentialResolver.ARG_ID, "secret/data/ssh");
        input.put(CredentialResolver.ARG_TYPE, "ssh_private_key");
        Map result = cr.resolve(input);
        assertEquals("ssh-user", result.get(CredentialResolver.VAL_USER));
        assertEquals("foo", result.get(CredentialResolver.VAL_PKEY));
    }

    @Test
    public void testCustomCA() throws IOException {
        CredentialResolver cr = new CredentialResolver(properties(agent.getTLSAddress(), certPem, false)::get);
        HashMap<String, String> input = new HashMap<>();
        input.put(CredentialResolver.ARG_ID, "secret/data/ssh");
        input.put(CredentialResolver.ARG_TYPE, "ssh_private_key");
        Map result = cr.resolve(input);
        assertEquals("ssh-user", result.get(CredentialResolver.VAL_USER));
        assertEquals("foo", result.get(CredentialResolver.VAL_PKEY));
    }

    private static void assertErrorContains(Exception e, String s) {
        assertTrue(String.format("Expected '%s' message but got: %s", s, e.getMessage()), Pattern.matches(".*" + s.toLowerCase()  + ".*", e.getMessage().toLowerCase()));
    }

    private static JsonObject get(String path) throws IOException {
        HttpGet get = new HttpGet(url(path));
        get.setHeader("X-Vault-Token", "root");
        return gson.fromJson(CredentialResolver.send(get, "", false), JsonObject.class);
    }

    private static JsonObject put(String path, String data) throws IOException {
        HttpPut put = new HttpPut(url(path));
        if (data != null) {
            put.setEntity(new StringEntity(data));
        }
        put.setHeader("X-Vault-Token", "root");
        return gson.fromJson(CredentialResolver.send(put, "", false), JsonObject.class);
    }

    private static String url(String path) {
        return String.format("%s/v1/%s", vault.getAddress(), path);
    }

    private static String readResource(String path) {
        InputStream policyResource = Thread.currentThread().getContextClassLoader().getResourceAsStream(path);
        assertNotNull(policyResource);
        return new Scanner(policyResource, "UTF-8").useDelimiter("\\A").next();
    }

    private static HashMap<String, String> properties(String address, String ca, Boolean skipTLS) {
        HashMap<String, String> props = new HashMap<>();
        if (address != null) {
            props.put("mid.external_credentials.vault.address", address);
        }
        if (ca != null) {
            props.put("mid.external_credentials.vault.ca", ca);
        }
        if (skipTLS != null) {
            props.put("mid.external_credentials.vault.tls_skip_verify", skipTLS.toString());
        }

        return props;
    }
}
