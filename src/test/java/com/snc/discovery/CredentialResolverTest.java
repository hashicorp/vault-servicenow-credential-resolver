package com.snc.discovery;

import com.github.tomakehurst.wiremock.junit.WireMockRule;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;
import org.junit.function.ThrowingRunnable;

import static com.github.tomakehurst.wiremock.client.WireMock.*;

import java.util.HashMap;
import java.util.Map;

public class CredentialResolverTest {
    @Rule
    public WireMockRule wireMockRule = new WireMockRule();

    private Map setupAndResolve(String path, String json) {
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
    public void testResolveKvV2() {
        var result = setupAndResolve("secret/data/ssh", "{'data':{'data':{'username':'ssh-user','private_key':'my_very_private_key'}}}");

        Assert.assertEquals("ssh-user", result.get(CredentialResolver.VAL_USER));
        Assert.assertEquals("my_very_private_key", result.get(CredentialResolver.VAL_PKEY));
        Assert.assertEquals(2, result.size());
    }

    @Test
    public void testResolveBasic() {
        var result = setupAndResolve("kv/user", "{'data':{'username':'my-user','password':'my-password'}}");

        Assert.assertEquals("my-user", result.get(CredentialResolver.VAL_USER));
        Assert.assertEquals("my-password", result.get(CredentialResolver.VAL_PSWD));
        Assert.assertEquals(2, result.size());
    }

    @Test
    public void testResolveSshWithPasswordAndPassphrase() {
        var result = setupAndResolve("kv/ssh-with-passphrase", "{'data':{'username':'ssh-user','password':'ssh-password','private_key':'ssh-private-key','passphrase':'ssh-passphrase'}}");

        Assert.assertEquals("ssh-user", result.get(CredentialResolver.VAL_USER));
        Assert.assertEquals("ssh-password", result.get(CredentialResolver.VAL_PSWD));
        Assert.assertEquals("ssh-private-key", result.get(CredentialResolver.VAL_PKEY));
        Assert.assertEquals("ssh-passphrase", result.get(CredentialResolver.VAL_PASSPHRASE));
        Assert.assertEquals(4, result.size());
    }

    @Test
    public void testResolveActiveDirectoryFields() {
        var result = setupAndResolve("ad/ad-user", "{'data':{'username':'my-user','password':'my-password','current_password':'my-current-password'}}");

        Assert.assertEquals("my-user", result.get(CredentialResolver.VAL_USER));
        Assert.assertEquals("my-current-password", result.get(CredentialResolver.VAL_PSWD));
        Assert.assertEquals(2, result.size());
    }

    @Test
    public void testResolveAwsFields() {
        var result = setupAndResolve("aws/aws-user", "{'data':{'username':'aws-user','password':'aws-password','current_password':'aws-current-password','access_key':'aws-access-key','secret_key':'aws-secret-key'}}");

        Assert.assertEquals("aws-access-key", result.get(CredentialResolver.VAL_USER));
        Assert.assertEquals("aws-secret-key", result.get(CredentialResolver.VAL_PSWD));
        Assert.assertEquals(2, result.size());
    }
}
