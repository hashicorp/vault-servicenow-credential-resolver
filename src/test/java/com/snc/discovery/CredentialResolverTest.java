package com.snc.discovery;

import com.github.tomakehurst.wiremock.junit.WireMockRule;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;

import static com.github.tomakehurst.wiremock.client.WireMock.*;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.HashMap;

public class CredentialResolverTest {
    @Rule
    public WireMockRule wireMockRule = new WireMockRule();

    @Test
    public void testResolve(){
        stubFor(get("/v1/secret/data/ssh")
                .withHeader("accept", containing("application/json"))
                .willReturn(ok()
                        .withHeader("Content-Type", "application/json")
                        .withBody("{'data':{'username':'ssh-user','private_key':'my_very_private_key'}}")));

        var cr = new CredentialResolver(prop -> "http://localhost:8080");
        var input = new HashMap<String, String>();
        input.put(CredentialResolver.ARG_ID, "secret/data/ssh");
        var result = cr.resolve(input);
        Assert.assertEquals("ssh-user", result.get(CredentialResolver.VAL_USER));
        Assert.assertEquals("my_very_private_key", result.get(CredentialResolver.VAL_PKEY));

        // These keys should not be set.
        Assert.assertNull(result.get(CredentialResolver.VAL_PSWD));
        Assert.assertNull(result.get(CredentialResolver.VAL_PASSPHRASE));
    }
}
