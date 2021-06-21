package com.snc.discovery;

import junit.framework.TestCase;

import java.util.HashMap;

public class CredentialResolverTest extends TestCase {
    public void testConstructor() {
        var testMain = new CredentialResolver();
    }

    public void testResolve() {
        var cr = new CredentialResolver();
        cr.resolve(new HashMap<String, String>());
    }
}
