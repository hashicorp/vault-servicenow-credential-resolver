package com.snc.discovery;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Serializable;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Objects;
import javax.net.ssl.*;

/**
 * <p>A container for SSL-related configuration options, meant to be stored within a {@link CredentialResolver} instance.</p>
 *
 * <p>Borrowed from https://github.com/BetterCloud/vault-java-driver</p>
 *
 * <p>Construct instances of this class using a builder pattern, calling setter methods for each value and then
 * terminating with a call to build().</p>
 */
public class TLSConfig implements Serializable {

    private static final long serialVersionUID = 1L;

    private boolean verify;
    private transient SSLContext sslContext;
    private String pemUTF8;  // exposed to unit tests
    private Boolean verifyObject;

    /**
     * A dummy SSLContext, for use when SSL verification is disabled.  Overwrites Java's default server certificate
     * verification process, to always trust any certificates.
     */
    private static SSLContext DISABLED_SSL_CONTEXT;

    static {
        try {
            DISABLED_SSL_CONTEXT = SSLContext.getInstance("TLS");
            DISABLED_SSL_CONTEXT.init(null, new TrustManager[]{new X509TrustManager() {
                @Override
                public void checkClientTrusted(final X509Certificate[] x509Certificates, final String s) throws CertificateException {
                }

                @Override
                public void checkServerTrusted(final X509Certificate[] x509Certificates, final String s) throws CertificateException {
                }

                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }
            }}, new java.security.SecureRandom());
        } catch (NoSuchAlgorithmException | KeyManagementException e) {
            e.printStackTrace();
        }
    }

    /**
     * <p>Whether or not HTTPS connections to the Vault server should verify that a valid SSL certificate is being
     * used.  Unless this is set to <code>false</code>, the default behavior is to always verify SSL certificates.</p>
     *
     * <p>SSL CERTIFICATE VERIFICATION SHOULD NOT BE DISABLED IN PRODUCTION!  This feature is made available to
     * facilitate development or testing environments, where you might be using a self-signed cert that will not
     * pass verification.  However, even if you are using a self-signed cert on your Vault server, you can still leave
     * SSL verification enabled and have your application supply the cert using <code>pemFile()</code>,
     * <code>pemResource()</code>, or <code>pemUTF8()</code>.</p>
     *
     * @param verify Whether or not to verify the SSL certificate used by Vault with HTTPS connections.  Default is <code>true</code>.
     * @return This object, with verify populated, ready for additional builder-pattern method calls or else finalization with the build() method
     */
    public TLSConfig verify(final Boolean verify) {
        this.verifyObject = verify;
        return this;
    }

    /**
     * <p>An X.509 certificate, to use when communicating with Vault over HTTPS.  This method accepts a string
     * containing the certificate data.  This string should meet the following requirements:</p>
     *
     * <ul>
     *     <li>Contain an unencrypted X.509 certificate, in PEM format.</li>
     *     <li>Use UTF-8 encoding.</li>
     *     <li>
     *          Contain a line-break between the certificate header (e.g. "-----BEGIN CERTIFICATE-----") and the
     *          rest of the certificate content.  It doesn't matter whether or not there are additional line
     *          breaks within the certificate content, or whether there is a line break before the certificate
     *          footer (e.g. "-----END CERTIFICATE-----").  But the Java standard library will fail to properly
     *          process the certificate without a break following the header
     *          (see http://www.doublecloud.org/2014/03/reading-x-509-certificate-in-java-how-to-handle-format-issue/).
     *      </li>
     * </ul>
     *
     * <p>If no certificate data is provided, either by this method or <code>pemFile()</code>
     * or <code>pemResource()</code>, then <code>TLSConfig</code> will look to the
     * <code>VAULT_SSL_CERT</code> environment variable.</p>
     *
     * @param pemUTF8 An X.509 certificate, in unencrypted PEM format with UTF-8 encoding.
     * @return This object, with pemUTF8 populated, ready for additional builder-pattern method calls or else finalization with the build() method
     */
    public TLSConfig pemUTF8(final String pemUTF8) {
        this.pemUTF8 = pemUTF8;
        return this;
    }

    /**
     * <p>This is the terminating method in the builder pattern.  The method that validates all of the fields that
     * has been set already, uses environment variables when available to populate any unset fields, and returns
     * a <code>TLSConfig</code> object that is ready for use.</p>
     *
     * @return This object, with all available config options parsed and loaded
     * @throws TLSException If SSL certificate verification is enabled, and any problem occurs while trying to build an SSLContext
     */
    public TLSConfig build() throws TLSException {
        this.verify = true;
        if (this.verifyObject != null) {
            this.verify = verifyObject;
        }

        if (verify && pemUTF8 != null) {
            this.sslContext = buildSslContextFromPem();
        } else if (!verify) {
            this.sslContext = DISABLED_SSL_CONTEXT;
        }
        return this;
    }

    public boolean isVerify() {
        return verify;
    }

    public SSLContext getSslContext() {
        return sslContext;
    }

    protected String getPemUTF8() {
        return pemUTF8;
    }

    /**
     * Constructs an SSLContext, when server cert data was provided in PEM format.
     *
     * @return An SSLContext, constructed with the PEM data supplied.
     * @throws TLSException
     */
    private SSLContext buildSslContextFromPem() throws TLSException {
        try {
            final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");

            TrustManager[] trustManagers = null;
            if (pemUTF8 != null) {
                final TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                // Convert the trusted servers PEM data into an X509Certificate
                X509Certificate certificate;
                try (final ByteArrayInputStream pem = new ByteArrayInputStream(pemUTF8.getBytes(StandardCharsets.UTF_8))) {
                    certificate = (X509Certificate) certificateFactory.generateCertificate(pem);
                }
                // Build a truststore
                final KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
                keyStore.load(null);
                keyStore.setCertificateEntry("caCert", certificate);
                trustManagerFactory.init(keyStore);
                trustManagers = trustManagerFactory.getTrustManagers();
            }

            final SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustManagers, null);
            return sslContext;
        } catch (CertificateException | IOException | NoSuchAlgorithmException | KeyStoreException | KeyManagementException e) {
            throw new TLSException(e);
        }
    }

    /**
     * A utility method for extracting content from an {@link InputStream} into a UTF-8 encoded {@link String}.  Used
     * by the various methods in this class that load PEM data from files or classpath resources.
     *
     * @param input An InputStream, presumably containing PEM data with UTF-8 encoding
     * @return A UTF-8 encoded String, containing all of the InputStream's content
     * @throws IOException
     */
    private static String inputStreamToUTF8(final InputStream input) throws IOException {
        final BufferedReader in = new BufferedReader(new InputStreamReader(input, StandardCharsets.UTF_8));
        final StringBuilder utf8 = new StringBuilder();
        String str;
        while ((str = in.readLine()) != null) {
            // String concatenation is less efficient, but for some reason the line-breaks (which are necessary
            // for Java to correctly parse SSL certs) are stripped off when using a StringBuilder.
            utf8.append(str).append(System.lineSeparator());
        }
        in.close();
        return utf8.toString();
    }

    public static class TLSException extends Exception {

        public TLSException(final Throwable t) {
            super(t);
        }
    }
}
