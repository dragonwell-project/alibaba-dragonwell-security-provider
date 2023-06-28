package com.alibaba.dragonwell.security.tls.demo;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.conscrypt.OpenSSLX509Certificate;

public class CertificateBuild {
    private static final char[] EMPTY_PASSWORD = new char[0];
    private static final String SERVER_CA = "/cert/sm2-root.crt";
    private static final String PRIVATE_KEY = "/cert/sm2-root.key";
    private static KeyStore ks = null;

    static {
        try {
            // Create an empty keystore
            ks = KeyStore.getInstance("PKCS12", new BouncyCastleProvider());
            ks.load(null, null);

            // Build a service CA
            X509Certificate ca = OpenSSLX509Certificate
                    .fromX509PemInputStream(CertificateBuild.class.getResourceAsStream(SERVER_CA));
            PrivateKey privateKey = readSM2PrivateKeyPemFile(PRIVATE_KEY);

            ks.setKeyEntry("default", privateKey, EMPTY_PASSWORD, new X509Certificate[] { ca });
            ks.setCertificateEntry("CA", ca);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static PrivateKey readSM2PrivateKeyPemFile(String name) throws Exception {
        InputStream inputStream = CertificateBuild.class.getResourceAsStream(name);
        InputStreamReader inputStreamReader = new InputStreamReader(inputStream);
        BufferedReader bufferedReader = new BufferedReader(inputStreamReader);
        StringBuilder sb = new StringBuilder();
        String line = null;
        while ((line = bufferedReader.readLine()) != null) {
            if (line.startsWith("-")) {
                continue;
            }
            sb.append(line).append("\n");
        }
        String ecKey = sb.toString().replaceAll("\\r\\n|\\r|\\n", "");
        Base64.Decoder base64Decoder = Base64.getDecoder();
        byte[] keyByte = base64Decoder.decode(ecKey.getBytes(StandardCharsets.UTF_8));
        PKCS8EncodedKeySpec eks2 = new PKCS8EncodedKeySpec(keyByte);
        KeyFactory keyFactory = KeyFactory.getInstance("EC", new BouncyCastleProvider());
        PrivateKey privateKey = keyFactory.generatePrivate(eks2);
        return privateKey;
    }

    public static KeyManager[] keyManagerBuilder() throws Exception {
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(ks, EMPTY_PASSWORD);
        return kmf.getKeyManagers();
    }

    public static TrustManager[] trustManagerBuilder() throws Exception {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);
        return tmf.getTrustManagers();
    }
}
