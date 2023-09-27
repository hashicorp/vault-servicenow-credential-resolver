/*
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

package com.snc.discovery;

import com.github.tomakehurst.wiremock.junit.WireMockRule;
import org.junit.Assert;
import org.junit.Rule;
import org.junit.Test;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.*;

public class CredentialResolverTest {
    @Rule
    public WireMockRule wireMockRule = new WireMockRule();

    private Map setupAndResolve(String path, String json) throws IOException {
        stubFor(get("/v1/" + path)
            .withHeader("accept", containing("application/json"))
            .willReturn(ok()
                .withHeader("Content-Type", "application/json")
                .withBody(json)));

        CredentialResolver cr = new CredentialResolver(CredentialResolverTest::testProperty);
        HashMap<String, String> input = new HashMap<>();
        input.put(CredentialResolver.ARG_ID, path);
        return cr.resolve(input);
    }

    private static String testProperty(String p) {
        HashMap<String, String> properties = new HashMap<>();
        properties.put(CredentialResolver.PROP_ADDRESS, "http://localhost:8080");

        return properties.get(p);
    }

    @Test
    public void testNoVaultAddressSpecified() {
        CredentialResolver cr = new CredentialResolver((prop) -> null);
        Exception exception = Assert.assertThrows(RuntimeException.class, () -> cr.resolve(new HashMap<>()));
        Assert.assertTrue(exception.getMessage().contains(String.format("MID server property %s is empty but required", CredentialResolver.PROP_ADDRESS)));
    }

    @Test
    public void testNoData() {
        stubFor(get("/v1/no-data")
            .withHeader("accept", containing("application/json"))
            .willReturn(ok()
                .withHeader("Content-Type", "application/json")
                .withBody("{}")));

        CredentialResolver cr = new CredentialResolver(CredentialResolverTest::testProperty);
        HashMap<String, String> input = new HashMap<>();
        input.put(CredentialResolver.ARG_ID, "no-data");

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
    public void testResolveSnmpV3Fields() throws IOException {
        Map result = setupAndResolve("kv/snmpv3-creds", "{'data':{'username':'snmpv3-user','authprotocol':'the-authprotocol','authkey':'the-authkey','privprotocol':'the-privprotocol','privkey':'the-privkey'}}");

        Assert.assertEquals("snmpv3-user", result.get(CredentialResolver.VAL_USER));
        Assert.assertEquals("the-authprotocol", result.get(CredentialResolver.VAL_AUTHPROTO));
        Assert.assertEquals("the-authkey", result.get(CredentialResolver.VAL_AUTHKEY));
        Assert.assertEquals("the-privprotocol", result.get(CredentialResolver.VAL_PRIVPROTO));
        Assert.assertEquals("the-privkey", result.get(CredentialResolver.VAL_PRIVKEY));
        Assert.assertEquals(5, result.size());
    }

    @Test
    public void testValidateResultFullyPopulated() {
        CredentialResolver cr = new CredentialResolver(prop -> "");
        HashMap<String, String> input = new HashMap<>();
        input.put(CredentialResolver.VAL_USER, "");
        input.put(CredentialResolver.VAL_PSWD, "");
        input.put(CredentialResolver.VAL_PKEY, "");
        input.put(CredentialResolver.VAL_PASSPHRASE, "");
        input.put(CredentialResolver.VAL_AUTHPROTO, "");
        input.put(CredentialResolver.VAL_AUTHKEY, "");
        input.put(CredentialResolver.VAL_PRIVPROTO, "");
        input.put(CredentialResolver.VAL_PRIVKEY, "");
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
