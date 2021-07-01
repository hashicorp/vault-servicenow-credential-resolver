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

        var cr = new CredentialResolver(prop -> "http://localhost:8080");
        var input = new HashMap<String, String>();
        input.put(CredentialResolver.ARG_ID, path);
        return cr.resolve(input);
    }

    @Test
    public void testDegenerateCase() {
        stubFor(get("/v1/degenerate")
            .withHeader("accept", containing("application/json"))
            .willReturn(ok()
                .withHeader("Content-Type", "application/json")
                .withBody("{}")));

        var cr = new CredentialResolver(prop -> "http://localhost:8080");
        var input = new HashMap<String, String>();
        input.put(CredentialResolver.ARG_ID, "degenerate");

        var exception = Assert.assertThrows(RuntimeException.class, () -> cr.resolve(input));
        Assert.assertTrue(exception.getMessage().contains("No data found"));
    }

    @Test
    public void testResolveKvV2() throws IOException {
        var result = setupAndResolve("secret/data/ssh", "{'data':{'data':{'username':'ssh-user','private_key':'my_very_private_key'}}}");

        Assert.assertEquals("ssh-user", result.get(CredentialResolver.VAL_USER));
        Assert.assertEquals("my_very_private_key", result.get(CredentialResolver.VAL_PKEY));
        Assert.assertEquals(2, result.size());
    }

    @Test
    public void testResolveBasic() throws IOException {
        var result = setupAndResolve("kv/user", "{'data':{'username':'my-user','password':'my-password'}}");

        Assert.assertEquals("my-user", result.get(CredentialResolver.VAL_USER));
        Assert.assertEquals("my-password", result.get(CredentialResolver.VAL_PSWD));
        Assert.assertEquals(2, result.size());
    }

    @Test
    public void testResolveSshWithPasswordAndPassphrase() throws IOException {
        var result = setupAndResolve("kv/ssh-with-passphrase", "{'data':{'username':'ssh-user','password':'ssh-password','private_key':'ssh-private-key','passphrase':'ssh-passphrase'}}");

        Assert.assertEquals("ssh-user", result.get(CredentialResolver.VAL_USER));
        Assert.assertEquals("ssh-password", result.get(CredentialResolver.VAL_PSWD));
        Assert.assertEquals("ssh-private-key", result.get(CredentialResolver.VAL_PKEY));
        Assert.assertEquals("ssh-passphrase", result.get(CredentialResolver.VAL_PASSPHRASE));
        Assert.assertEquals(4, result.size());
    }

    @Test
    public void testResolveActiveDirectoryFields() throws IOException {
        var result = setupAndResolve("ad/ad-user", "{'data':{'username':'my-user','password':'my-password','current_password':'my-current-password'}}");

        Assert.assertEquals("my-user", result.get(CredentialResolver.VAL_USER));
        Assert.assertEquals("my-current-password", result.get(CredentialResolver.VAL_PSWD));
        Assert.assertEquals(2, result.size());
    }

    @Test
    public void testResolveAwsFields() throws IOException {
        var result = setupAndResolve("aws/aws-user", "{'data':{'username':'aws-user','password':'aws-password','current_password':'aws-current-password','access_key':'aws-access-key','secret_key':'aws-secret-key'}}");

        Assert.assertEquals("aws-access-key", result.get(CredentialResolver.VAL_USER));
        Assert.assertEquals("aws-secret-key", result.get(CredentialResolver.VAL_PSWD));
        Assert.assertEquals(2, result.size());
    }

    @Test
    public void testValidateResultFullyPopulated() {
        var cr = new CredentialResolver(prop -> "");
        var input = new HashMap<String, String>();
        input.put(CredentialResolver.VAL_USER, "");
        input.put(CredentialResolver.VAL_PSWD, "");
        input.put(CredentialResolver.VAL_PKEY, "");
        input.put(CredentialResolver.VAL_PASSPHRASE, "");
        for (var type : CredentialResolver.CredentialType.values()) {
            // No validation errors expected
            cr.validateResult(input, type);
        }

        cr.validateResult(input, null);
    }

    @Test
    public void testValidateResultEmpty() {
        var cr = new CredentialResolver(prop -> "");
        var input = new HashMap<String, String>();
        for (var type : CredentialResolver.CredentialType.values()) {
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
        var cr = new CredentialResolver(prop -> "");
        for (var type : CredentialResolver.CredentialType.values()) {
            var input = new HashMap<String, String>();
            for (var expected : type.expectedFields()) {
                input.put(expected, "");
            }
            // No validation errors expected
            cr.validateResult(input, type);
        }
    }
}
