package com.snc.discovery;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import com.github.tomakehurst.wiremock.junit.WireMockRule;

import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;

import static com.github.tomakehurst.wiremock.client.WireMock.containing;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.ok;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;

public class CredentialResolverTest {
    @Rule
    public WireMockRule wireMockRule = new WireMockRule();

    private Map setupAndResolve(String path, String json) throws IOException {
        stubFor(get("/v1/" + path)
            .withHeader("accept", containing("application/json"))
            .willReturn(ok()
                .withHeader("Content-Type", "application/json")
                .withBody(json)));

        CredentialResolver cr = new CredentialResolver(prop -> testProperty(prop));
        HashMap<String, String> input = new HashMap<>();
        input.put(CredentialResolver.ARG_ID, path);
        return cr.resolve(input);
    }

    private static String testProperty(String p) {
        var properties = new HashMap<String, String>();
        properties.put("mid.external_credentials.vault.address", "http://localhost:8080");

        return properties.get(p);
    }

    @Test
    public void testDegenerateCase() {
        stubFor(get("/v1/degenerate")
            .withHeader("accept", containing("application/json"))
            .willReturn(ok()
                .withHeader("Content-Type", "application/json")
                .withBody("{}")));

        CredentialResolver cr = new CredentialResolver(prop -> testProperty(prop));
        HashMap<String, String> input = new HashMap<>();
        input.put(CredentialResolver.ARG_ID, "degenerate");

        Exception exception = Assert.assertThrows(RuntimeException.class, () -> cr.resolve(input));
        Assert.assertTrue(exception.getMessage().contains("No data found"));
    }

    @Test
    public void testResolveKvV2() throws IOException {
        Map result = setupAndResolve("secret/data/ssh", "{'data':{'data':{'username':'ssh-user','private_key':'my_very_private_key'}}}");

        Assert.assertEquals("ssh-user", result.get(CredentialResolver.VAL_USER));
        Assert.assertEquals("my_very_private_key", result.get(CredentialResolver.VAL_PKEY));
        Assert.assertEquals(2, result.size());
    }

    @Test
    public void testResolveBasic() throws IOException {
        Map result = setupAndResolve("kv/user", "{'data':{'username':'my-user','password':'my-password'}}");

        Assert.assertEquals("my-user", result.get(CredentialResolver.VAL_USER));
        Assert.assertEquals("my-password", result.get(CredentialResolver.VAL_PSWD));
        Assert.assertEquals(2, result.size());
    }

    @Test
    public void testResolveSshWithPasswordAndPassphrase() throws IOException {
        Map result = setupAndResolve("kv/ssh-with-passphrase", "{'data':{'username':'ssh-user','password':'ssh-password','private_key':'ssh-private-key','passphrase':'ssh-passphrase'}}");

        Assert.assertEquals("ssh-user", result.get(CredentialResolver.VAL_USER));
        Assert.assertEquals("ssh-password", result.get(CredentialResolver.VAL_PSWD));
        Assert.assertEquals("ssh-private-key", result.get(CredentialResolver.VAL_PKEY));
        Assert.assertEquals("ssh-passphrase", result.get(CredentialResolver.VAL_PASSPHRASE));
        Assert.assertEquals(4, result.size());
    }

    @Test
    public void testResolveActiveDirectoryFields() throws IOException {
        Map result = setupAndResolve("ad/ad-user", "{'data':{'username':'my-user','password':'my-password','current_password':'my-current-password'}}");

        Assert.assertEquals("my-user", result.get(CredentialResolver.VAL_USER));
        Assert.assertEquals("my-current-password", result.get(CredentialResolver.VAL_PSWD));
        Assert.assertEquals(2, result.size());
    }

    @Test
    public void testResolveAwsFields() throws IOException {
        Map result = setupAndResolve("aws/aws-user", "{'data':{'username':'aws-user','password':'aws-password','current_password':'aws-current-password','access_key':'aws-access-key','secret_key':'aws-secret-key'}}");

        Assert.assertEquals("aws-access-key", result.get(CredentialResolver.VAL_USER));
        Assert.assertEquals("aws-secret-key", result.get(CredentialResolver.VAL_PSWD));
        Assert.assertEquals(2, result.size());
    }

    @Test
    public void testValidateResultFullyPopulated() {
        CredentialResolver cr = new CredentialResolver(prop -> "");
        HashMap<String, String> input = new HashMap<>();
        input.put(CredentialResolver.VAL_USER, "");
        input.put(CredentialResolver.VAL_PSWD, "");
        input.put(CredentialResolver.VAL_PKEY, "");
        input.put(CredentialResolver.VAL_PASSPHRASE, "");
        for (CredentialResolver.CredentialType type : CredentialResolver.CredentialType.values()) {
            // No validation errors expected
            cr.validateResult(input, type);
        }

        cr.validateResult(input, null);
    }

    @Test
    public void testValidateResultEmpty() {
        CredentialResolver cr = new CredentialResolver(prop -> "");
        HashMap<String, String> input = new HashMap<>();
        for (CredentialResolver.CredentialType type : CredentialResolver.CredentialType.values()) {
            // All types should error for empty input
            Assert.assertThrows(RuntimeException.class, () -> cr.validateResult(input, type));
        }

        // null type only validates non-empty
        Assert.assertThrows(RuntimeException.class, () -> cr.validateResult(input, null));
        input.put("FOO_KEY", "");
        // Now that there is some data in the input, no further validation should take place.
        cr.validateResult(input, null);
    }

    @Test
    public void testValidateResultMinimallyPopulated() {
        CredentialResolver cr = new CredentialResolver(prop -> "");
        for (CredentialResolver.CredentialType type : CredentialResolver.CredentialType.values()) {
            HashMap<String, String> input = new HashMap<>();
            for (String expected : type.expectedFields()) {
                input.put(expected, "");
            }
            // No validation errors expected
            cr.validateResult(input, type);
        }
    }
}
