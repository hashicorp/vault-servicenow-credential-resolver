package com.snc.discovery;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;
import java.util.*;
import com.google.gson.Gson;

public class CredentialResolver {
    private final HttpClient httpClient;

    public CredentialResolver() {
        httpClient = HttpClient.newHttpClient();
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
        //Config.get().getProperty()
        String id = (String) args.get(ARG_ID);

        var request = HttpRequest.newBuilder()
                .uri(URI.create("http://127.0.0.1:8300/v1/" + id))
                .header("accept", "application/json")
                .header("X-Vault-Request", "true")
                .build();

        HttpResponse<String> response;
        try {
            response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        } catch(Exception e) {
            throw new RuntimeException("Failed to query Vault for secret with credential ID: " + id, e);
        }

        Gson gson = new Gson();
        var secret = gson.fromJson(response.body(), VaultSecret.class);
        var data = secret.getData();

        // Check for embedded "data" field to handle kv-v2.
        if (data.get("data") != null) {
            try {
                data = data.get("data").getAsJsonObject();
            } catch (IllegalStateException e) {
                // If it's not a JsonObject, then it's not kv-v2 and we use the top-level "Data" field.
            }
        }

        var username = data.get("username");
        if (data.has("access_key")) {
            username = data.get("access_key");
        }
        var password = data.get("password");
        if (data.has("current_password")) {
            password = data.get("current_password");
        }
        if (data.has("secret_key")) {
            password = data.get("secret_key");
        }
        var passphrase = data.get("passphrase");
        var privateKey = data.get("private_key");

        var result = new HashMap<String, String>();
        if (username != null) {
            result.put(VAL_USER, username.getAsString());
        }
        if (password != null) {
            result.put(VAL_PSWD, password.getAsString());
        }
        if (privateKey != null) {
            result.put(VAL_PKEY, privateKey.getAsString());
        }
        if (passphrase != null) {
            result.put(VAL_PASSPHRASE, passphrase.getAsString());
        }

        System.err.println("Queried Vault for credential id: "+id);

        return result;
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
