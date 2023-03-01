package com.alibaba.dragonwell.security.tls.demo;

import java.io.ByteArrayInputStream;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import com.tencent.kona.crypto.CryptoInsts;
import com.tencent.kona.pkix.PKIXInsts;
import com.tencent.kona.ssl.SSLInsts;

public class KonaCertificateBuild {
    protected final static Cert[] TRUSTED_CERTS = { Cert.CA_ECDSA_SECP256R1 };
    protected final static Cert[] END_ENTITY_CERTS = { Cert.EE_ECDSA_SECP256R1 };
    private static KeyStore ts = null; // trust store
    private static KeyStore ks = null; // key store
    private static char passphrase[] = "passphrase".toCharArray();

    static {
        try {
            // Generate certificate from cert string.
            CertificateFactory cf = PKIXInsts.getCertificateFactory("X.509");

            // Import the trused certs.
            ByteArrayInputStream is;
            if (TRUSTED_CERTS != null && TRUSTED_CERTS.length != 0) {
                ts = PKIXInsts.getKeyStore("PKCS12");
                ts.load(null, null);

                Certificate[] trustedCert = new Certificate[TRUSTED_CERTS.length];
                for (int i = 0; i < TRUSTED_CERTS.length; i++) {
                    is = new ByteArrayInputStream(TRUSTED_CERTS[i].certStr.getBytes());
                    try {
                        trustedCert[i] = cf.generateCertificate(is);
                    } finally {
                        is.close();
                    }

                    ts.setCertificateEntry(
                            "trusted-cert-" + TRUSTED_CERTS[i].name(), trustedCert[i]);
                }
            }

            // Import the key materials.
            if (END_ENTITY_CERTS != null && END_ENTITY_CERTS.length != 0) {
                ks = PKIXInsts.getKeyStore("PKCS12");
                ks.load(null, null);

                for (int i = 0; i < END_ENTITY_CERTS.length; i++) {
                    // generate the private key.
                    PKCS8EncodedKeySpec priKeySpec = new PKCS8EncodedKeySpec(
                            Base64.getMimeDecoder().decode(END_ENTITY_CERTS[i].privKeyStr));
                    KeyFactory kf = CryptoInsts.getKeyFactory(
                            END_ENTITY_CERTS[i].keyAlgo);
                    PrivateKey priKey = kf.generatePrivate(priKeySpec);

                    // generate certificate chain
                    is = new ByteArrayInputStream(
                            END_ENTITY_CERTS[i].certStr.getBytes());
                    Certificate keyCert = null;
                    try {
                        keyCert = cf.generateCertificate(is);
                    } finally {
                        is.close();
                    }

                    Certificate[] chain = new Certificate[] { keyCert };

                    // import the key entry.
                    ks.setKeyEntry("cert-" + END_ENTITY_CERTS[i].name(),
                            priKey, passphrase, chain);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static KeyManager[] keyManagerBuilder() throws Exception {
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("NewSunX509");
        kmf.init(ks, passphrase);
        return kmf.getKeyManagers();
    }

    public static TrustManager[] trustManagerBuilder() throws Exception {
        TrustManagerFactory tmf =
                SSLInsts.getTrustManagerFactory("PKIX");
        tmf.init(ts);
        return tmf.getTrustManagers();
    }

    public static enum Cert {

        CA_ECDSA_SECP256R1(
                "EC",
                // SHA256withECDSA, curve secp256r1
                // Validity
                // Not Before: May 22 07:18:16 2018 GMT
                // Not After : May 17 07:18:16 2038 GMT
                // Subject Key Identifier:
                // 60:CF:BD:73:FF:FA:1A:30:D2:A4:EC:D3:49:71:46:EF:1A:35:A0:86
                "-----BEGIN CERTIFICATE-----\n" +
                        "MIIBvjCCAWOgAwIBAgIJAIvFG6GbTroCMAoGCCqGSM49BAMCMDsxCzAJBgNVBAYT\n" +
                        "AlVTMQ0wCwYDVQQKDARKYXZhMR0wGwYDVQQLDBRTdW5KU1NFIFRlc3QgU2VyaXZj\n" +
                        "ZTAeFw0xODA1MjIwNzE4MTZaFw0zODA1MTcwNzE4MTZaMDsxCzAJBgNVBAYTAlVT\n" +
                        "MQ0wCwYDVQQKDARKYXZhMR0wGwYDVQQLDBRTdW5KU1NFIFRlc3QgU2VyaXZjZTBZ\n" +
                        "MBMGByqGSM49AgEGCCqGSM49AwEHA0IABBz1WeVb6gM2mh85z3QlvaB/l11b5h0v\n" +
                        "LIzmkC3DKlVukZT+ltH2Eq1oEkpXuf7QmbM0ibrUgtjsWH3mULfmcWmjUDBOMB0G\n" +
                        "A1UdDgQWBBRgz71z//oaMNKk7NNJcUbvGjWghjAfBgNVHSMEGDAWgBRgz71z//oa\n" +
                        "MNKk7NNJcUbvGjWghjAMBgNVHRMEBTADAQH/MAoGCCqGSM49BAMCA0kAMEYCIQCG\n" +
                        "6wluh1r2/T6L31mZXRKf9JxeSf9pIzoLj+8xQeUChQIhAJ09wAi1kV8yePLh2FD9\n" +
                        "2YEHlSQUAbwwqCDEVB5KxaqP\n" +
                        "-----END CERTIFICATE-----",
                "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg/HcHdoLJCdq3haVd\n" +
                        "XZTSKP00YzM3xX97l98vGL/RI1KhRANCAAQc9VnlW+oDNpofOc90Jb2gf5ddW+Yd\n" +
                        "LyyM5pAtwypVbpGU/pbR9hKtaBJKV7n+0JmzNIm61ILY7Fh95lC35nFp"),

        EE_ECDSA_SECP256R1(
                "EC",
                // SHA256withECDSA, curve secp256r1
                // Validity
                // Not Before: May 22 07:18:16 2018 GMT
                // Not After : May 17 07:18:16 2038 GMT
                // Authority Key Identifier:
                // 60:CF:BD:73:FF:FA:1A:30:D2:A4:EC:D3:49:71:46:EF:1A:35:A0:86
                "-----BEGIN CERTIFICATE-----\n" +
                        "MIIBqjCCAVCgAwIBAgIJAPLY8qZjgNRAMAoGCCqGSM49BAMCMDsxCzAJBgNVBAYT\n" +
                        "AlVTMQ0wCwYDVQQKDARKYXZhMR0wGwYDVQQLDBRTdW5KU1NFIFRlc3QgU2VyaXZj\n" +
                        "ZTAeFw0xODA1MjIwNzE4MTZaFw0zODA1MTcwNzE4MTZaMFUxCzAJBgNVBAYTAlVT\n" +
                        "MQ0wCwYDVQQKDARKYXZhMR0wGwYDVQQLDBRTdW5KU1NFIFRlc3QgU2VyaXZjZTEY\n" +
                        "MBYGA1UEAwwPUmVncmVzc2lvbiBUZXN0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcD\n" +
                        "QgAEb+9n05qfXnfHUb0xtQJNS4JeSi6IjOfW5NqchvKnfJey9VkJzR7QHLuOESdf\n" +
                        "xlR7q8YIWgih3iWLGfB+wxHiOqMjMCEwHwYDVR0jBBgwFoAUYM+9c//6GjDSpOzT\n" +
                        "SXFG7xo1oIYwCgYIKoZIzj0EAwIDSAAwRQIgWpRegWXMheiD3qFdd8kMdrkLxRbq\n" +
                        "1zj8nQMEwFTUjjQCIQDRIrAjZX+YXHN9b0SoWWLPUq0HmiFIi8RwMnO//wJIGQ==\n" +
                        "-----END CERTIFICATE-----",
                "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgn5K03bpTLjEtFQRa\n" +
                        "JUtx22gtmGEvvSUSQdimhGthdtihRANCAARv72fTmp9ed8dRvTG1Ak1Lgl5KLoiM\n" +
                        "59bk2pyG8qd8l7L1WQnNHtAcu44RJ1/GVHurxghaCKHeJYsZ8H7DEeI6");

        final String keyAlgo;
        final String certStr;
        final String privKeyStr;

        Cert(String keyAlgo, String certStr, String privKeyStr) {
            this.keyAlgo = keyAlgo;
            this.certStr = certStr;
            this.privKeyStr = privKeyStr;
        }
    }
}
