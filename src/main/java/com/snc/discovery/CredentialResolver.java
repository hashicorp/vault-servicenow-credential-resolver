package com.snc.discovery;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;
import java.util.function.Function;

import com.google.gson.Gson;
import com.google.gson.JsonObject;

import com.service_now.mid.services.Config;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

public class CredentialResolver {
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
    public Map resolve(Map args) throws IOException {
        String vaultAddress = getProperty.apply("mid.external_credentials.vault.address");
        String id = (String) args.get(ARG_ID);

        String body;
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpGet get = new HttpGet(vaultAddress + "/v1/" + id);
            get.setHeader("accept", "application/json");
            get.setHeader("X-Vault-Request", "true");
            try (CloseableHttpResponse response = httpClient.execute(get)) {
                Scanner s = new Scanner(response.getEntity().getContent()).useDelimiter("\\A");
                body = s.hasNext() ? s.next() : "";

                int status = response.getStatusLine().getStatusCode();
                if (status < 200 || status > 299) {
                    String message = String.format("Failed to query Vault for credential id: %s. Status code %d.", id, status);
                    Gson gson = new Gson();
                    VaultError error = gson.fromJson(body, VaultError.class);
                    if (error != null) {
                        message += " Errors: " + Arrays.toString(error.errors);
                    }

                    throw new RuntimeException(message);
                }
            }
        }

        System.err.println("Successfully queried Vault for credential id: "+id);

        Map<String, String> result = extractKeys(body);
        CredentialType type = lookupByName((String) args.get(ARG_TYPE));
        validateResult(result, type);
        return result;
    }

    private Map<String, String> extractKeys(String vaultResponse) {
        Gson gson = new Gson();
        VaultSecret secret = gson.fromJson(vaultResponse, VaultSecret.class);
        JsonObject data = secret.getData();

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
        KeyAndSource username = keyAndSourceFromData(data, "access_key", "username");
        // secret_key for AWS secret engine, current_password for AD secret engine
        KeyAndSource password = keyAndSourceFromData(data, "secret_key", "current_password", "password");
        KeyAndSource privateKey = keyAndSourceFromData(data, "private_key");
        KeyAndSource passphrase = keyAndSourceFromData(data, "passphrase");

        System.err.printf("Setting values from fields %s=%s, %s=%s, %s=%s, %s=%s%n",
                VAL_USER, username.source,
                VAL_PSWD, password.source,
                VAL_PKEY, privateKey.source,
                VAL_PASSPHRASE, passphrase.source);
        HashMap<String, String> result = new HashMap<>();
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

    public void validateResult(Map<String, String> result, CredentialType type) {
        if (result.size() == 0) {
            throw new RuntimeException("No fields to extract from Vault secret");
        }

        if (type == null) {
            return;
        }

        for (String expected : type.expectedFields()) {
            if (!result.containsKey(expected)) {
                throw new RuntimeException(String.format("Expected '%s' field for credential type %s", expected, type.name()));
            }
        }
    }

    private static final Map<String, CredentialType> nameIndex = new HashMap<>(CredentialType.values().length);
    static {
        for (CredentialType type : CredentialType.values()) {
            nameIndex.put(type.name(), type);
        }
    }
    private static CredentialType lookupByName(String name) {
        return nameIndex.get(name);
    }

    enum CredentialType {
        basic                               (new String[]{VAL_USER, VAL_PSWD}),
        windows                             (new String[]{VAL_USER, VAL_PSWD}),
        ssh_password                        (new String[]{VAL_USER, VAL_PSWD}),
        vmware                              (new String[]{VAL_USER, VAL_PSWD}),
        jdbc                                (new String[]{VAL_USER, VAL_PSWD}),
        jms                                 (new String[]{VAL_USER, VAL_PSWD}),
        aws                                 (new String[]{VAL_USER, VAL_PSWD}),
        ssh_private_key                     (new String[]{VAL_USER, VAL_PKEY}),
        sn_cfg_ansible                      (new String[]{VAL_USER, VAL_PKEY}),
        sn_disco_certmgmt_certificate_ca    (new String[]{VAL_USER, VAL_PKEY}),
        cfg_chef_credentials                (new String[]{VAL_USER, VAL_PKEY}),
        infoblox                            (new String[]{VAL_USER, VAL_PKEY}),
        api_key                             (new String[]{VAL_USER, VAL_PKEY});

        private final String[] expectedFields;

        CredentialType(String[] expectedFields) {
            this.expectedFields = expectedFields;
        }

        public String[] expectedFields() {
            return expectedFields;
        }
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

    private static class VaultSecret {
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

    private static class VaultError {
        private String[] errors;

        public String[] getErrors() {
            return errors;
        }
    }
}
