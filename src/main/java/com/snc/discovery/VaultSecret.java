package com.snc.discovery;

import com.google.gson.JsonObject;

public class VaultSecret {
    private JsonObject data;
    private String[] warnings;

    public JsonObject getData() {
        return data;
    }

    public String[] getWarnings() {
        return warnings;
    }
}
