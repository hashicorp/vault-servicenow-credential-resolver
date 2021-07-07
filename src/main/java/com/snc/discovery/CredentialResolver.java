package com.snc.discovery;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.service_now.mid.services.Config;
import org.apache.http.client.HttpResponseException;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;
import java.util.function.Function;

public class CredentialResolver {
    private static final CloseableHttpClient httpClient = HttpClients.createDefault();
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

        String body = send(new HttpGet(vaultAddress + "/v1/" + id));
        System.err.println("Successfully queried Vault for credential id: "+id);

        Map<String, String> result = extractKeys(body);
        CredentialType type = lookupByName((String) args.get(ARG_TYPE));
        validateResult(result, type);
        return result;
    }

    /**
     * Return the ServiceNow API version supported by this class.
     */
    public String getVersion() {
        return "1.0";
    }

    public static String send(HttpUriRequest req) throws IOException {
        String body = null;
        req.setHeader("accept", "application/json");
        req.setHeader("X-Vault-Request", "true");
        try (CloseableHttpResponse response = httpClient.execute(req)) {
            if (response.getEntity() != null) {
                Scanner s = new Scanner(response.getEntity().getContent()).useDelimiter("\\A");
                body = s.hasNext() ? s.next() : "";
            }

            int status = response.getStatusLine().getStatusCode();
            if (status < 200 || status >= 300) {
                String message = String.format("Failed to query Vault URL: %s.", req.getURI());
                Gson gson = new Gson();
                VaultError json = gson.fromJson(body, VaultError.class);
                if (json != null) {
                    final String[] errors = json.getErrors();
                    if (errors != null && errors.length > 0) {
                        message += String.format(" Errors: %s.", Arrays.toString(errors));
                    }
                    final String[] warnings = json.getWarnings();
                    if (warnings != null && warnings.length > 0) {
                        message += String.format(" Warnings: %s.", Arrays.toString(warnings));
                    }
                }

                throw new HttpResponseException(status, message);
            }
        }

        return body;
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
        ValueAndSource username = valueAndSourceFromData(data, "access_key", "username");
        // secret_key for AWS secret engine, current_password for AD secret engine
        ValueAndSource password = valueAndSourceFromData(data, "secret_key", "current_password", "password");
        ValueAndSource privateKey = valueAndSourceFromData(data, "private_key");
        ValueAndSource passphrase = valueAndSourceFromData(data, "passphrase");

        System.err.printf("Setting values from fields %s=%s, %s=%s, %s=%s, %s=%s%n",
                VAL_USER, username.source,
                VAL_PSWD, password.source,
                VAL_PKEY, privateKey.source,
                VAL_PASSPHRASE, passphrase.source);
        HashMap<String, String> result = new HashMap<>();
        if (username.value != null) {
            result.put(VAL_USER, username.value);
        }
        if (password.value != null) {
            result.put(VAL_PSWD, password.value);
        }
        if (privateKey.value != null) {
            result.put(VAL_PKEY, privateKey.value);
        }
        if (passphrase.value != null) {
            result.put(VAL_PASSPHRASE, passphrase.value);
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
    private static class ValueAndSource {
        private final String value;
        private final String source;

        ValueAndSource(String value, String source) {
            this.value = value;
            this.source = source;
        }
    }

    // The first key that exists in data will be extracted and returned.
    private ValueAndSource valueAndSourceFromData(JsonObject data, String ...keys) {
        for (String key : keys) {
            if (data.has(key)) {
                return new ValueAndSource(data.get(key).getAsString(), key);
            }
        }

        return new ValueAndSource(null, null);
    }
}
