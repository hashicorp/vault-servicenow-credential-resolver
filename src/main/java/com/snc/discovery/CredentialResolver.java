package com.snc.discovery;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.*;
import java.util.*;
import java.io.*;
import com.google.gson.Gson;

/**
 * Basic implementation of a CredentialResolver that uses a properties file.
 */

public class CredentialResolver {

    private static String ENV_VAR = "CREDENTIAL_RESOLVER_FILE";
    private static String DEFAULT_PROP_FILE_PATH = "C:\\dummycredentials.properties";

    // These are the permissible names of arguments passed INTO the resolve()
    // method.

    // the string identifier as configured on the ServiceNow instance...
    public static final String ARG_ID = "id";

    // a dotted-form string IPv4 address (like "10.22.231.12") of the target
    // system...
    public static final String ARG_IP = "ip";

    // the string type (ssh, snmp, etc.) of credential as configured on the
    // instance...
    public static final String ARG_TYPE = "type";

    // the string MID server making the request, as configured on the
    // instance...
    public static final String ARG_MID = "mid";

    // These are the permissible names of values returned FROM the resolve()
    // method.

    // the string user name for the credential, if needed...
    public static final String VAL_USER = "user";

    // the string password for the credential, if needed...
    public static final String VAL_PSWD = "pswd";

    // the string pass phrase for the credential if needed:
    public static final String VAL_PASSPHRASE = "passphrase";

    // the string private key for the credential, if needed...
    public static final String VAL_PKEY = "pkey";

    // the string authentication protocol for the credential, if needed...
    public static final String VAL_AUTHPROTO = "authprotocol";

    // the string authentication key for the credential, if needed...
    public static final String VAL_AUTHKEY = "authkey";

    // the string privacy protocol for the credential, if needed...
    public static final String VAL_PRIVPROTO = "privprotocol";

    // the string privacy key for the credential, if needed...
    public static final String VAL_PRIVKEY = "privkey";


    private Properties fProps;

    public CredentialResolver() {
    }

//    private void loadProps() {
//        if(fProps == null)
//            fProps = new Properties();
//
//        try {
//            String propFilePath = System.getenv(ENV_VAR);
//            if(propFilePath == null) {
//                System.err.println("Environment var "+ENV_VAR+" not found. Using default file: "+DEFAULT_PROP_FILE_PATH);
//                propFilePath = DEFAULT_PROP_FILE_PATH;
//            }
//
//            File propFile = new File(propFilePath);
//            if(!propFile.exists() || !propFile.canRead()) {
//                System.err.println("Can't open "+propFile.getAbsolutePath());
//            }
//            else {
//                InputStream propsIn = new FileInputStream(propFile);
//                fProps.load(propsIn);
//            }
//            //fProps.load(CredentialResolver.class.getClassLoader().getResourceAsStream("dummycredentials.properties"));
//        } catch (IOException e) {
//            System.err.println("Problem loading credentials file:");
//            e.printStackTrace();
//        }
//    }

    /**
     * Resolve a credential.
     */
    public Map resolve(Map args) {
        //loadProps();
        String id = (String) args.get(ARG_ID);
        String type = (String) args.get(ARG_TYPE);
        //String keyPrefix = id+"."+type+".";

//        if(id.equalsIgnoreCase("misbehave"))
//            throw new RuntimeException("I've been a baaaaaaaaad CredentialResolver!");

        // create a client
        var client = HttpClient.newHttpClient();

        // create a request
        var request = HttpRequest.newBuilder(
                URI.create("http://127.0.0.1:8200/v1/secret/data/ssh"))
                .header("accept", "application/json")
                .header("X-Vault-Request", "true")
                .header("X-Vault-Token", "root")
                .build();

        // use the client to send the request
        HttpResponse<String> response;
        try {
            response = client.send(request, HttpResponse.BodyHandlers.ofString());
        } catch(IOException e) {
            return null;
        } catch(InterruptedException e) {
            return null;
        }
        //var j = new JSONObject(response.body());
        //j.get("foo").

        // the response:
        //System.out.println(response.body());

        Gson gson = new Gson();
        var secret = gson.fromJson(response.body(), VaultSecret.class);
        System.out.println(secret.Data());

        // the resolved credential is returned in a HashMap...
        Map result = new HashMap();
        result.put(VAL_USER, "ssh-user");
        //result.put(VAL_PSWD, fProps.get(keyPrefix + VAL_PSWD));
        result.put(VAL_PKEY, "FOO");
        //result.put(VAL_PASSPHRASE, fProps.get(keyPrefix + VAL_PASSPHRASE));
        //result.put(VAL_AUTHPROTO, fProps.get(keyPrefix + VAL_AUTHPROTO));
        //result.put(VAL_AUTHKEY, fProps.get(keyPrefix + VAL_AUTHKEY));
        //result.put(VAL_PRIVPROTO, fProps.get(keyPrefix + VAL_PRIVPROTO));
        //result.put(VAL_PRIVKEY, fProps.get(keyPrefix + VAL_PRIVKEY));

        System.err.println("Did some phony resolving for credential id/type["+id+"/"+type+"]");

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
        //obj.loadProps();

        System.err.println("I spy the following credentials: ");
        for(Object key: obj.fProps.keySet()) {
            System.err.println(key+": "+obj.fProps.get(key));
        }
    }
}
