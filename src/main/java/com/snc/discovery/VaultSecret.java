package com.snc.discovery;

import com.google.gson.JsonObject;

class VaultSecret {
    private String requestID;
    private String leaseID;
    private Integer leaseDuration;
    private Boolean renewable;
    private JsonObject data;
    private String[] warnings;
    // Auth omitted
    // WrapInfo omitted

    public String getRequestID() {
        return requestID;
    }

    public String getLeaseID() {
        return leaseID;
    }

    public Integer getLeaseDuration() {
        return leaseDuration;
    }

    public Boolean getRenewable() {
        return renewable;
    }

    public JsonObject getData() {
        return data;
    }

    public String[] getWarnings() {
        return warnings;
    }

    VaultSecret() {
    }
}
