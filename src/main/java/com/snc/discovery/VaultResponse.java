package com.snc.discovery;

import com.google.gson.JsonObject;

public class VaultResponse {
    private JsonObject data;
    private String[] warnings;
    private String[] errors;

    public JsonObject getData() {
        return data;
    }

    public String[] getWarnings() {
        return warnings;
    }

    public String[] getErrors() {
        return errors;
    }
}
