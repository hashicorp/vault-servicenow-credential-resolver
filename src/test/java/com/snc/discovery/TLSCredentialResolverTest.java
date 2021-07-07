package com.snc.discovery;

import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLPeerUnverifiedException;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static com.github.tomakehurst.wiremock.client.WireMock.ok;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;

public class TLSCredentialResolverTest {
    @Rule
    public WireMockRule wireMockRule = new WireMockRule(options()
        .httpsPort(8443)
        .httpDisabled(true)
        .bindAddress("localhost"));

    private Map setupAndResolve(String path, String json) throws IOException {
//        WireMock.configureFor("https", "localhost", 8443);
        stubFor(get("/v1/" + path)
            .withHeader("accept", containing("application/json"))
            .willReturn(ok()
                .withHeader("Content-Type", "application/json")
                .withBody(json)));

        CredentialResolver cr = new CredentialResolver(prop -> testProperty(prop, "", ""));
        HashMap<String, String> input = new HashMap<>();
        input.put(CredentialResolver.ARG_ID, path);
        return cr.resolve(input);
    }

    private static String testProperty(String p, String skip_verify, String ca) {
        HashMap<String, String> properties = new HashMap<>();
        properties.put("mid.external_credentials.vault.address", "https://localhost:8443");
        if (skip_verify.length() > 0) {
            properties.put("mid.external_credentials.vault.tls_skip_verify", skip_verify);
        }
        if (ca.length() > 0) {
            properties.put("mid.external_credentials.vault.ca", ca);
        }

        return properties.get(p);
    }

    @Test
    public void testNoCustomSSLContext() {
        stubFor(get("/v1/anything")
            .withHeader("accept", containing("application/json"))
            .willReturn(ok()
                .withHeader("Content-Type", "application/json")
                .withBody("{}")));

        CredentialResolver cr = new CredentialResolver(prop -> testProperty(prop, "", ""));
        HashMap<String, String> input = new HashMap<>();
        input.put(CredentialResolver.ARG_ID, "anything");

        Assert.assertThrows(SSLException.class, () -> cr.resolve(input));
    }

//    @Test
//    public void testTLSSkipVerify() throws IOException {
//        WireMock.configureFor("https", "localhost", 8443);
//        stubFor(get("/v1/kv/user")
//            .withHeader("accept", containing("application/json"))
//            .willReturn(ok()
//                .withHeader("Content-Type", "application/json")
//                .withBody("{'data':{'username':'my-user','password':'my-password'}}")));
//
//        var cr = new CredentialResolver(prop -> testProperty(prop, "true", ""));
//        var input = new HashMap<String, String>();
//        input.put(CredentialResolver.ARG_ID, "kv/user");
//
//        var result = cr.resolve(input);
//        Assert.assertEquals("my-user", result.get(CredentialResolver.VAL_USER));
//        Assert.assertEquals("my-password", result.get(CredentialResolver.VAL_PSWD));
//        Assert.assertEquals(2, result.size());
//    }
}
