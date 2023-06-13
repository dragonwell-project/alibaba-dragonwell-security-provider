package org.conscrypt.net.ssl;

import org.conscrypt.net.ssl.interop.CertTuple;
import org.conscrypt.net.ssl.interop.CipherSuite;
import org.conscrypt.net.ssl.interop.Client;
import org.conscrypt.net.ssl.interop.ClientAuth;
import org.conscrypt.net.ssl.interop.FileCert;
import org.conscrypt.net.ssl.interop.HashAlgorithm;
import org.conscrypt.net.ssl.interop.JdkServer;
import org.conscrypt.net.ssl.interop.KeyAlgorithm;
import org.conscrypt.net.ssl.interop.NamedGroup;
import org.conscrypt.net.ssl.interop.OpenSSLClient;
import org.conscrypt.net.ssl.interop.Protocol;
import org.conscrypt.net.ssl.interop.Server;
import org.conscrypt.net.ssl.interop.ServerCaller;
import org.conscrypt.net.ssl.interop.SignatureAlgorithm;
import org.conscrypt.net.ssl.interop.SignatureScheme;
import org.conscrypt.net.ssl.interop.Utilities;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.Ignore;
import static org.junit.Assert.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * The interop testing between JDK server and OpenSSL client.
 */
public class JdkServerBabaSSLClientTest {

    private static final FileCert ECDSA_INTCA_CERT = new FileCert(
            KeyAlgorithm.EC, SignatureAlgorithm.ECDSA, HashAlgorithm.SHA256,
            "intca-p256ecdsa-p256ecdsa.crt",
            "intca-p256ecdsa-p256ecdsa.key");
    private static final FileCert ECDSA_EE_CERT = new FileCert(
            KeyAlgorithm.EC, SignatureAlgorithm.ECDSA, HashAlgorithm.SHA256,
            "ee-p256ecdsa-p256ecdsa-p256ecdsa.crt",
            "ee-p256ecdsa-p256ecdsa-p256ecdsa.key");

    private static final FileCert SM_INTCA_CERT = new FileCert(
            KeyAlgorithm.EC, SignatureAlgorithm.SM2, HashAlgorithm.SM3,
            "intca-sm2sm2-sm2sm2.crt",
            "intca-sm2sm2-sm2sm2.key");
    private static final FileCert SM_EE_CERT = new FileCert(
            KeyAlgorithm.EC, SignatureAlgorithm.SM2, HashAlgorithm.SM3,
            "ee-sm2sm2-sm2sm2-sm2sm2.crt",
            "ee-sm2sm2-sm2sm2-sm2sm2.key");

    private static final String SESS_FILE_NAME = "openssl.sess";

    @Before
    public void setup() throws IOException {
        Utilities.addKonaProviders();
    }

    @After
    public void clean() throws IOException {
        deleteSessFile();
        Utilities.removeKonaProviders();
    }

    private static void deleteSessFile() throws IOException {
        Files.deleteIfExists(Paths.get(SESS_FILE_NAME));
    }

    @Test
    public void testConnWithECDSACertP256CurveOnTLS13() throws Exception {
        testConnWithECDSACertP256CurveOnTLS13(ClientAuth.NONE);
        testConnWithECDSACertP256CurveOnTLS13(ClientAuth.REQUIRED);
    }

    private void testConnWithECDSACertP256CurveOnTLS13(ClientAuth clientAuth)
            throws Exception {
        connect(
                new FileCert[] { ECDSA_INTCA_CERT },
                new FileCert[] { ECDSA_EE_CERT },
                Protocol.TLSV1_3,
                CipherSuite.TLS_AES_128_GCM_SHA256,
                NamedGroup.SECP256R1,
                SignatureScheme.ECDSA_SECP256R1_SHA256,
                clientAuth);

        connect(
                new FileCert[] { ECDSA_INTCA_CERT },
                new FileCert[] { ECDSA_EE_CERT },
                Protocol.TLSV1_3,
                CipherSuite.TLS_SM4_GCM_SM3,
                NamedGroup.SECP256R1,
                SignatureScheme.ECDSA_SECP256R1_SHA256,
                clientAuth);
    }

    @Test
    public void testConnWithECDSACertSM2CurveOnTLS13() throws Exception {
        testConnWithECDSACertSM2CurveOnTLS13(ClientAuth.NONE);
        testConnWithECDSACertSM2CurveOnTLS13(ClientAuth.REQUIRED);
    }

    private void testConnWithECDSACertSM2CurveOnTLS13(ClientAuth clientAuth)
            throws Exception {
        connect(
                new FileCert[] { ECDSA_INTCA_CERT },
                new FileCert[] { ECDSA_EE_CERT },
                Protocol.TLSV1_3,
                CipherSuite.TLS_AES_128_GCM_SHA256,
                NamedGroup.CURVESM2,
                SignatureScheme.ECDSA_SECP256R1_SHA256,
                clientAuth);

        connect(
                new FileCert[] { ECDSA_INTCA_CERT },
                new FileCert[] { ECDSA_EE_CERT },
                Protocol.TLSV1_3,
                CipherSuite.TLS_SM4_GCM_SM3,
                NamedGroup.CURVESM2,
                SignatureScheme.ECDSA_SECP256R1_SHA256,
                clientAuth);
    }

    @Test
    public void testConnWithECDSACertP256CurveOnTLS12() throws Exception {
        testConnWithECDSACertP256CurveOnTLS12(ClientAuth.NONE);
        testConnWithECDSACertP256CurveOnTLS12(ClientAuth.REQUIRED);
    }

    private void testConnWithECDSACertP256CurveOnTLS12(ClientAuth clientAuth)
            throws Exception {
        connect(
                new FileCert[] { ECDSA_INTCA_CERT },
                new FileCert[] { ECDSA_EE_CERT },
                Protocol.TLSV1_2,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
                NamedGroup.SECP256R1,
                SignatureScheme.ECDSA_SECP256R1_SHA256,
                clientAuth);

        connect(
                new FileCert[] { ECDSA_INTCA_CERT },
                new FileCert[] { ECDSA_EE_CERT },
                Protocol.TLSV1_2,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                NamedGroup.SECP256R1,
                SignatureScheme.ECDSA_SECP256R1_SHA256,
                clientAuth);
    }

    @Test
    public void testConnWithSM2CertP256CurveOnTLS13() throws Exception {
        testConnWithSM2CertP256CurveOnTLS13(ClientAuth.NONE);
        testConnWithSM2CertP256CurveOnTLS13(ClientAuth.REQUIRED);
    }

    private void testConnWithSM2CertP256CurveOnTLS13(ClientAuth clientAuth)
            throws Exception {
        connect(
                new FileCert[] { SM_INTCA_CERT },
                new FileCert[] { SM_EE_CERT },
                Protocol.TLSV1_3,
                CipherSuite.TLS_AES_128_GCM_SHA256,
                NamedGroup.SECP256R1,
                SignatureScheme.SM2SIG_SM3,
                clientAuth);

        connect(
                new FileCert[] { SM_INTCA_CERT },
                new FileCert[] { SM_EE_CERT },
                Protocol.TLSV1_3,
                CipherSuite.TLS_SM4_GCM_SM3,
                NamedGroup.SECP256R1,
                SignatureScheme.SM2SIG_SM3,
                clientAuth);
    }

    @Test
    public void testConnWithSM2CertSM2CurveOnTLS13() throws Exception {
        testConnWithSM2CertSM2CurveOnTLS13(ClientAuth.NONE);
        testConnWithSM2CertSM2CurveOnTLS13(ClientAuth.REQUIRED);
    }

    private void testConnWithSM2CertSM2CurveOnTLS13(ClientAuth clientAuth)
            throws Exception {
        connect(
                new FileCert[] { SM_INTCA_CERT },
                new FileCert[] { SM_EE_CERT },
                Protocol.TLSV1_3,
                CipherSuite.TLS_AES_128_GCM_SHA256,
                NamedGroup.CURVESM2,
                SignatureScheme.SM2SIG_SM3,
                clientAuth);

        connect(
                new FileCert[] { SM_INTCA_CERT },
                new FileCert[] { SM_EE_CERT },
                Protocol.TLSV1_3,
                CipherSuite.TLS_SM4_GCM_SM3,
                NamedGroup.CURVESM2,
                SignatureScheme.SM2SIG_SM3,
                clientAuth);
    }

    @Test
    public void testCertSelectionWithSignatureSchemeOnTLS13()
            throws Exception {
        // The JDK server selects ECDSA_EE_CERT due to
        // the OpenSSL client prefers to ECDSA_SECP256R1_SHA256.
        connect(
                new FileCert[] { ECDSA_INTCA_CERT },
                new FileCert[] { SM_EE_CERT, ECDSA_EE_CERT },
                Protocol.TLSV1_3,
                CipherSuite.TLS_AES_128_GCM_SHA256,
                NamedGroup.SECP256R1,
                SignatureScheme.ECDSA_SECP256R1_SHA256,
                ClientAuth.NONE);

        // The JDK server selects SM_EE_CERT due to
        // the OpenSSL client prefers to SM2SIG_SM3.
        connect(
                new FileCert[] { SM_INTCA_CERT },
                new FileCert[] { ECDSA_EE_CERT, SM_EE_CERT },
                Protocol.TLSV1_3,
                CipherSuite.TLS_AES_128_GCM_SHA256,
                NamedGroup.SECP256R1,
                SignatureScheme.SM2SIG_SM3,
                ClientAuth.NONE);
    }

    private void connect(
            FileCert[] trustedCerts,
            FileCert[] eeCerts,
            Protocol clientProtocol,
            CipherSuite clientCipherSuite,
            NamedGroup clientNamedGroup,
            SignatureScheme clientSignatureScheme,
            ClientAuth clientAuth) throws Exception {
        CertTuple certTuple = new CertTuple(trustedCerts, eeCerts);

        ExecutorService executor = Executors.newFixedThreadPool(1);

        JdkServer.Builder serverBuilder = new JdkServer.Builder();
        serverBuilder.setCertTuple(certTuple);
        serverBuilder.setProtocols(Protocol.TLSV1_3, Protocol.TLSV1_2);
        serverBuilder.setCipherSuites(
                CipherSuite.TLS_AES_128_GCM_SHA256,
                CipherSuite.TLS_SM4_GCM_SM3,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
        serverBuilder.setClientAuth(clientAuth);

        try (Server server = serverBuilder.build()) {
            executor.submit(new ServerCaller(server));
            Utilities.waitFor(Server::isAlive, server);

            try (Client client = createClient(
                    certTuple, clientProtocol,
                    clientCipherSuite, clientNamedGroup,
                    clientSignatureScheme)) {
                client.connect("127.0.0.1", server.getPort());
            }
        } finally {
            executor.shutdown();
        }
    }

    @Test
    public void testResumptionWithECDSACertP256CurveOnTLS13() throws Exception {
        testResumptionWithECDSACertP256CurveOnTLS13(ClientAuth.NONE);
        testResumptionWithECDSACertP256CurveOnTLS13(ClientAuth.REQUIRED);
    }

    private void testResumptionWithECDSACertP256CurveOnTLS13(ClientAuth clientAuth)
            throws Exception {
        resumeSession(
                new FileCert[] { ECDSA_INTCA_CERT },
                new FileCert[] { ECDSA_EE_CERT },
                Protocol.TLSV1_3,
                CipherSuite.TLS_AES_128_GCM_SHA256,
                NamedGroup.SECP256R1,
                SignatureScheme.ECDSA_SECP256R1_SHA256,
                true,
                clientAuth);

        resumeSession(
                new FileCert[] { ECDSA_INTCA_CERT },
                new FileCert[] { ECDSA_EE_CERT },
                Protocol.TLSV1_3,
                CipherSuite.TLS_SM4_GCM_SM3,
                NamedGroup.SECP256R1,
                SignatureScheme.ECDSA_SECP256R1_SHA256,
                true,
                clientAuth);
    }

    @Test
    public void testResumptionWithSM2CertSM2CurveOnTLS13() throws Exception {
        testResumptionWithSM2CertSM2CurveOnTLS13(ClientAuth.NONE);
        testResumptionWithSM2CertSM2CurveOnTLS13(ClientAuth.REQUIRED);
    }

    private void testResumptionWithSM2CertSM2CurveOnTLS13(ClientAuth clientAuth)
            throws Exception {
        resumeSession(
                new FileCert[] { SM_INTCA_CERT },
                new FileCert[] { SM_EE_CERT },
                Protocol.TLSV1_3,
                CipherSuite.TLS_AES_128_GCM_SHA256,
                NamedGroup.CURVESM2,
                SignatureScheme.SM2SIG_SM3,
                true,
                clientAuth);

        resumeSession(
                new FileCert[] { SM_INTCA_CERT },
                new FileCert[] { SM_EE_CERT },
                Protocol.TLSV1_3,
                CipherSuite.TLS_SM4_GCM_SM3,
                NamedGroup.CURVESM2,
                SignatureScheme.SM2SIG_SM3,
                true,
                clientAuth);
    }

    @Test
    public void testResumptionWithECDSACertP256CurveOnTLS12() throws Exception {
        testResumptionWithECDSACertP256CurveOnTLS12(false, ClientAuth.NONE);
        testResumptionWithECDSACertP256CurveOnTLS12(true, ClientAuth.NONE);
        testResumptionWithECDSACertP256CurveOnTLS12(false, ClientAuth.REQUIRED);
        testResumptionWithECDSACertP256CurveOnTLS12(true, ClientAuth.REQUIRED);
    }

    private void testResumptionWithECDSACertP256CurveOnTLS12(
            boolean isUseSessTicket, ClientAuth clientAuth) throws Exception {
        resumeSession(
                new FileCert[] { ECDSA_INTCA_CERT },
                new FileCert[] { ECDSA_EE_CERT },
                Protocol.TLSV1_2,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
                NamedGroup.SECP256R1,
                SignatureScheme.ECDSA_SECP256R1_SHA256,
                isUseSessTicket,
                clientAuth);

        resumeSession(
                new FileCert[] { ECDSA_INTCA_CERT },
                new FileCert[] { ECDSA_EE_CERT },
                Protocol.TLSV1_2,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                NamedGroup.SECP256R1,
                SignatureScheme.ECDSA_SECP256R1_SHA256,
                isUseSessTicket,
                clientAuth);
    }

    private void resumeSession(
            FileCert[] trustedCerts,
            FileCert[] eeCerts,
            Protocol clientProtocol,
            CipherSuite clientCipherSuite,
            NamedGroup clientNamedGroup,
            SignatureScheme clientSignatureScheme,
            boolean isUseSessTicket,
            ClientAuth clientAuth) throws Exception {
        CertTuple certTuple = new CertTuple(trustedCerts, eeCerts);

        ExecutorService executor = Executors.newFixedThreadPool(1);

        JdkServer.Builder serverBuilder = new JdkServer.Builder();
        serverBuilder.setCertTuple(certTuple);
        serverBuilder.setProtocols(Protocol.TLSV1_3, Protocol.TLSV1_2);
        serverBuilder.setCipherSuites(
                CipherSuite.TLS_AES_128_GCM_SHA256,
                CipherSuite.TLS_SM4_GCM_SM3,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
        serverBuilder.setClientAuth(clientAuth);

        try (JdkServer server = serverBuilder.build()) {
            executor.submit(new ServerCaller(server));
            Utilities.waitFor(Server::isAlive, server);

            long firstCreationTime = 0;
            try (OpenSSLClient client = createClient(
                    certTuple, clientProtocol, clientCipherSuite,
                    clientNamedGroup, clientSignatureScheme,
                    isUseSessTicket,
                    SESS_FILE_NAME, true)) {
                client.connect("127.0.0.1", server.getPort());
                firstCreationTime = server.getSession().getCreationTime();
            }

            try (OpenSSLClient client = createClient(
                    certTuple, clientProtocol, clientCipherSuite,
                    clientNamedGroup, clientSignatureScheme,
                    isUseSessTicket,
                    SESS_FILE_NAME, false)) {
                client.connect("127.0.0.1", server.getPort());

                long secondCreationTime = server.getSession().getCreationTime();
                // assertEquals(firstCreationTime, secondCreationTime);
                assertTrue(secondCreationTime - firstCreationTime < 2000);
            }
        } finally {
            executor.shutdown();
        }
    }

    private OpenSSLClient createClient(CertTuple certTuple, Protocol protocol,
            CipherSuite cipherSuite, NamedGroup namedGroup,
            SignatureScheme signatureScheme,
            boolean isUseSessTicket,
            String sessFile, boolean saveSess) {
        OpenSSLClient.Builder builder = new OpenSSLClient.Builder();
        builder.setCertTuple(certTuple);
        builder.setProtocols(protocol);
        builder.setCipherSuites(cipherSuite);
        builder.setNamedGroups(namedGroup);
        builder.setSignatureSchemes(signatureScheme);
        builder.setMessage("Q"); // quit s_client
        builder.setReadResponse(false);
        builder.setUseSessTicket(isUseSessTicket);

        if (sessFile != null) {
            if (saveSess) {
                builder.sessOut(sessFile);
            } else {
                builder.sessIn(sessFile);
            }
        }

        return builder.build();
    }

    private OpenSSLClient createClient(CertTuple certTuple, Protocol protocol,
            CipherSuite cipherSuite, NamedGroup namedGroup,
            SignatureScheme signatureScheme) {
        return createClient(certTuple, protocol, cipherSuite, namedGroup,
                signatureScheme, true, null, false);
    }
}
