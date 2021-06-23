package com.snc.discovery;

import junit.framework.TestCase;

import java.util.HashMap;

public class CredentialResolverTest extends TestCase {
    public void testResolve() {
        var cr = new CredentialResolver();
        var map = new HashMap<String, String>();
        map.put(CredentialResolver.ARG_ID, "secret/data/ssh");
        var result = cr.resolve(map);
        assertEquals("ssh-user", (String) result.get(CredentialResolver.VAL_USER));
        assertNotNull(result.get(CredentialResolver.VAL_PKEY));

        // These keys should not be set.
        assertNull(result.get(CredentialResolver.VAL_PSWD));
        assertNull(result.get(CredentialResolver.VAL_PASSPHRASE));
    }
}
