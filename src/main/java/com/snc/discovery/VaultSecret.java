package com.snc.discovery;

import java.util.Map;

class VaultSecret {
    private String requestID;
    private String leaseID;
    private Integer leaseDuration;
    private Boolean Renewable;
    private Map<String, Object> data;
    private String[] warnings;
    // Auth
    // WrapInfo
    VaultSecret() {}

    public Map<String, Object> Data() {
        return data;
    }
}
