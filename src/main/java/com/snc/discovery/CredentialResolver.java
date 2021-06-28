package com.snc.discovery;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import com.google.gson.Gson;
import com.google.gson.JsonObject;

import com.service_now.mid.services.Config;

public class CredentialResolver {
    private final HttpClient httpClient = HttpClient.newHttpClient();
    private final Function<String, String> getProperty;

    public CredentialResolver() {
        getProperty = prop -> Config.get().getProperty(prop);
    }

    public CredentialResolver(Function<String, String> getProperty) {
        this.getProperty = getProperty;
    }

    // Populated keys on resolve's input `Map args`
    public static final String ARG_ID = "id"; // the string identifier as configured on the ServiceNow instance
    public static final String ARG_IP = "ip"; // a dotted-form string IPv4 address (like "10.22.231.12") of the target system
    public static final String ARG_TYPE = "type"; // the string type (ssh, snmp, etc.) of credential
    public static final String ARG_MID = "mid"; // the MID server making the request

    // Keys that may optionally be populated on resolve's output Map
    public static final String VAL_USER = "user"; // the string user name for the credential
    public static final String VAL_PSWD = "pswd"; // the string password for the credential
    public static final String VAL_PASSPHRASE = "passphrase"; // the string pass phrase for the credential
    public static final String VAL_PKEY = "pkey"; // the string private key for the credential

    /**
     * Resolve a credential.
     */
    public Map resolve(Map args) {
        var vaultAddress = getProperty.apply("mid.external_credentials.vault.address");
        String id = (String) args.get(ARG_ID);

        var request = HttpRequest.newBuilder()
                .uri(URI.create(vaultAddress + "/v1/" + id))
                .header("accept", "application/json")
                .header("X-Vault-Request", "true")
                .build();

        HttpResponse<String> response;
        try {
            response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        } catch(Exception e) {
            throw new RuntimeException("Failed to query Vault for secret with credential ID: " + id, e);
        }

        System.err.println("Successfully queried Vault for credential id: "+id);

        return extractKeys(response.body());
    }

    public Map<String, String> extractKeys(String vaultResponse) {
        Gson gson = new Gson();
        var secret = gson.fromJson(vaultResponse, VaultSecret.class);
        var data = secret.getData();

        if (data == null) {
            throw new RuntimeException("No data found in Vault secret");
        }

        // Check for embedded "data" object to handle kv-v2.
        if (data.has("data")) {
            try {
                data = data.get("data").getAsJsonObject();
            } catch (IllegalStateException e) {
                // If it's not a JsonObject, then it's not kv-v2 and we use the top-level "Data" field.
            }
        }

        // access_key for AWS secret engine
        var username = keyAndSourceFromData(data, "access_key", "username");
        // secret_key for AWS secret engine, current_password for AD secret engine
        var password = keyAndSourceFromData(data, "secret_key", "current_password", "password");
        var privateKey = keyAndSourceFromData(data, "private_key");
        var passphrase = keyAndSourceFromData(data, "passphrase");

        System.err.printf("Setting values from fields %s=%s, %s=%s, %s=%s, %s=%s%n",
                VAL_USER, username.source,
                VAL_PSWD, password.source,
                VAL_PKEY, privateKey.source,
                VAL_PASSPHRASE, passphrase.source);
        var result = new HashMap<String, String>();
        if (username.key != null) {
            result.put(VAL_USER, username.key);
        }
        if (password.key != null) {
            result.put(VAL_PSWD, password.key);
        }
        if (privateKey.key != null) {
            result.put(VAL_PKEY, privateKey.key);
        }
        if (passphrase.key != null) {
            result.put(VAL_PASSPHRASE, passphrase.key);
        }

        return result;
    }

    // Metadata class to help report which fields keys were extracted from.
    private static class KeyAndSource {
        private final String key;
        private final String source;

        KeyAndSource(String key, String source) {
            this.key = key;
            this.source = source;
        }
    }

    // The first key that exists in data will be extracted and returned.
    private KeyAndSource keyAndSourceFromData(JsonObject data, String ...keys) {
        for (String key : keys) {
            if (data.has(key)) {
                return new KeyAndSource(data.get(key).getAsString(), key);
            }
        }

        return new KeyAndSource(null, null);
    }

    /**
     * Return the API version supported by this class.
     */
    public String getVersion() {
        return "1.0";
    }

    public static void main(String[] args) {
        CredentialResolver obj = new CredentialResolver();
    }
}
