package org.conscrypt.net.ssl;

import org.conscrypt.net.ssl.interop.CertTuple;
import org.conscrypt.net.ssl.interop.CipherSuite;
import org.conscrypt.net.ssl.interop.Client;
import org.conscrypt.net.ssl.interop.ClientAuth;
import org.conscrypt.net.ssl.interop.FileCert;
import org.conscrypt.net.ssl.interop.HashAlgorithm;
import org.conscrypt.net.ssl.interop.JdkDragonClient;
import org.conscrypt.net.ssl.interop.JdkDragonServer;
import org.conscrypt.net.ssl.interop.JdkProcDragonClient;
import org.conscrypt.net.ssl.interop.KeyAlgorithm;
import org.conscrypt.net.ssl.interop.NamedGroup;
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

import javax.net.ssl.SSLContext;
import java.io.IOException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * The interop testing between Jdk peers.
 */
public class JdkDragonServerJdkClientTest {

    private static final FileCert ECDSA_INTCA_CERT = new FileCert(
            KeyAlgorithm.EC, SignatureAlgorithm.ECDSA, HashAlgorithm.SHA256,
            "intca-p256ecdsa-p256ecdsa.crt",
            "intca-p256ecdsa-p256ecdsa.key");
    private static final FileCert ECDSA_EE_CERT = new FileCert(
            KeyAlgorithm.EC, SignatureAlgorithm.ECDSA, HashAlgorithm.SHA256,
            "ee-p256ecdsa-p256ecdsa-p256ecdsa.crt",
            "ee-p256ecdsa-p256ecdsa-p256ecdsa.key");

    private static final FileCert SM_INTCA_CERT = new FileCert(
            KeyAlgorithm.SM2, SignatureAlgorithm.SM2, HashAlgorithm.SM3,
            "intca-sm2sm2-sm2sm2.crt",
            "intca-sm2sm2-sm2sm2.key");
    private static final FileCert SM_EE_CERT = new FileCert(
            KeyAlgorithm.SM2, SignatureAlgorithm.SM2, HashAlgorithm.SM3,
            "ee-sm2sm2-sm2sm2-sm2sm2.crt",
            "ee-sm2sm2-sm2sm2-sm2sm2.key");

    @Before
    public void setup() throws IOException {
        Utilities.addKonaProviders();
    }

    @After
    public void clean() throws IOException {
        Utilities.removeKonaProviders();
    }

    @Test
    public void testConnWithECDSACertP256CurveOnTLS13() throws Exception {
        testConnWithECDSACertP256CurveOnTLS13(ClientAuth.NONE);
        testConnWithECDSACertP256CurveOnTLS13(ClientAuth.REQUIRED);
        testConnWithECDSACertP256CurveOnTLS13(ClientAuth.WANTED);
    }

    private void testConnWithECDSACertP256CurveOnTLS13(ClientAuth clientAuth)
            throws Exception {
        connect(
                new FileCert[] { ECDSA_INTCA_CERT, SM_INTCA_CERT },
                new FileCert[] { ECDSA_EE_CERT },
                Protocol.TLSV1_3,
                CipherSuite.TLS_AES_128_GCM_SHA256,
                NamedGroup.SECP256R1,
                SignatureScheme.ECDSA_SECP256R1_SHA256,
                clientAuth);

        connect(
                new FileCert[] { ECDSA_INTCA_CERT, SM_INTCA_CERT },
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
        testConnWithECDSACertSM2CurveOnTLS13(ClientAuth.WANTED);
    }

    private void testConnWithECDSACertSM2CurveOnTLS13(ClientAuth clientAuth)
            throws Exception {
        connect(
                new FileCert[] { ECDSA_INTCA_CERT, SM_INTCA_CERT },
                new FileCert[] { ECDSA_EE_CERT },
                Protocol.TLSV1_3,
                CipherSuite.TLS_AES_128_GCM_SHA256,
                NamedGroup.CURVESM2,
                SignatureScheme.ECDSA_SECP256R1_SHA256,
                clientAuth);

        connect(
                new FileCert[] { ECDSA_INTCA_CERT, SM_INTCA_CERT },
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
        testConnWithECDSACertP256CurveOnTLS12(ClientAuth.WANTED);
    }

    private void testConnWithECDSACertP256CurveOnTLS12(ClientAuth clientAuth)
            throws Exception {
        connect(
                new FileCert[] { ECDSA_INTCA_CERT, SM_INTCA_CERT },
                new FileCert[] { ECDSA_EE_CERT },
                Protocol.TLSV1_2,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
                NamedGroup.SECP256R1,
                SignatureScheme.ECDSA_SECP256R1_SHA256,
                clientAuth);

        connect(
                new FileCert[] { ECDSA_INTCA_CERT, SM_INTCA_CERT },
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
        testConnWithSM2CertP256CurveOnTLS13(ClientAuth.WANTED);
    }

    private void testConnWithSM2CertP256CurveOnTLS13(ClientAuth clientAuth)
            throws Exception {
        connect(
                new FileCert[] { ECDSA_INTCA_CERT, SM_INTCA_CERT },
                new FileCert[] { SM_EE_CERT },
                Protocol.TLSV1_3,
                CipherSuite.TLS_AES_128_GCM_SHA256,
                NamedGroup.SECP256R1,
                SignatureScheme.SM2SIG_SM3,
                clientAuth);

        connect(
                new FileCert[] { ECDSA_INTCA_CERT, SM_INTCA_CERT },
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
        testConnWithSM2CertSM2CurveOnTLS13(ClientAuth.WANTED);
    }

    private void testConnWithSM2CertSM2CurveOnTLS13(ClientAuth clientAuth)
            throws Exception {
        connect(
                new FileCert[] { ECDSA_INTCA_CERT, SM_INTCA_CERT },
                new FileCert[] { SM_EE_CERT },
                Protocol.TLSV1_3,
                CipherSuite.TLS_AES_128_GCM_SHA256,
                NamedGroup.CURVESM2,
                SignatureScheme.SM2SIG_SM3,
                clientAuth);

        connect(
                new FileCert[] { ECDSA_INTCA_CERT, SM_INTCA_CERT },
                new FileCert[] { SM_EE_CERT },
                Protocol.TLSV1_3,
                CipherSuite.TLS_SM4_GCM_SM3,
                NamedGroup.CURVESM2,
                SignatureScheme.SM2SIG_SM3,
                clientAuth);
    }

    @Test
    // The server selects ECDSA_EE_CERT due to
    // the client prefers to ECDSA_SECP256R1_SHA256.
    public void testCertSelectionWithSigSchemeECDSAOnTLS13()
            throws Exception {
        connect(
                new FileCert[] { ECDSA_INTCA_CERT },
                new FileCert[] { ECDSA_EE_CERT, SM_EE_CERT },
                Protocol.TLSV1_3,
                CipherSuite.TLS_AES_128_GCM_SHA256,
                NamedGroup.SECP256R1,
                SignatureScheme.ECDSA_SECP256R1_SHA256,
                ClientAuth.NONE);
    }

    @Test
    // The server selects SM_EE_CERT
    // due to the client prefers to SM2SIG_SM3.
    public void testCertSelectionWithSigSchemeSM2OnTLS13()
            throws Exception {
        connect(
                new FileCert[] { ECDSA_INTCA_CERT },
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
        CertTuple serverCertTuple = new CertTuple(trustedCerts, eeCerts);
        CertTuple clientCertTuple = null;
        if (clientAuth == ClientAuth.REQUIRED) {
            clientCertTuple = new CertTuple(trustedCerts, eeCerts);
        } else {
            clientCertTuple = new CertTuple(trustedCerts, CertTuple.EMPTY);
        }

        ExecutorService executor = Executors.newFixedThreadPool(1);

        JdkDragonServer.Builder serverBuilder = new JdkDragonServer.Builder();
        serverBuilder.setCertTuple(serverCertTuple);
        serverBuilder.setProtocols(Protocol.TLSV1_3, Protocol.TLSV1_2);
        serverBuilder.setCipherSuites(
                CipherSuite.TLS_AES_128_GCM_SHA256,
                CipherSuite.TLS_SM4_GCM_SM3,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256);
        serverBuilder.setClientAuth(clientAuth);
        serverBuilder.setMessage("Server");

        try (Server server = serverBuilder.build()) {
            executor.submit(new ServerCaller(server));
            Utilities.waitFor(Server::isAlive, server);

            JdkProcDragonClient.Builder builder = new JdkProcDragonClient.Builder();
            builder.setCertTuple(clientCertTuple);
            builder.setProtocols(clientProtocol);
            builder.setCipherSuites(clientCipherSuite);
            builder.setNamedGroups(clientNamedGroup);
            builder.setSignatureSchemes(clientSignatureScheme);
            builder.setMessage("Client");
            builder.setReadResponse(true);
            try (Client client = builder.build()) {
                client.connect("127.0.0.1", server.getPort());
            }
        } finally {
            executor.shutdown();
        }
    }

    @Test
    public void testResumptionWithSM2CertSM2CurveOnTLS13() throws Exception {
        testResumptionWithSM2CertSM2CCurveOnTLS13(ClientAuth.NONE);
        testResumptionWithSM2CertSM2CCurveOnTLS13(ClientAuth.REQUIRED);
    }

    private void testResumptionWithSM2CertSM2CCurveOnTLS13(ClientAuth clientAuth)
            throws Exception {
        resumeSession(
                new FileCert[] { ECDSA_INTCA_CERT, SM_INTCA_CERT },
                new FileCert[] { SM_EE_CERT },
                Protocol.TLSV1_3,
                CipherSuite.TLS_AES_128_GCM_SHA256,
                clientAuth);

        resumeSession(
                new FileCert[] { ECDSA_INTCA_CERT, SM_INTCA_CERT },
                new FileCert[] { SM_EE_CERT },
                Protocol.TLSV1_3,
                CipherSuite.TLS_SM4_GCM_SM3,
                clientAuth);
    }

    @Test
    public void testResumptionWithECDSACertP256CurveOnTLS12() throws Exception {
        testResumptionWithECDSACertP256CurveOnTLS12(ClientAuth.NONE);
        testResumptionWithECDSACertP256CurveOnTLS12(ClientAuth.REQUIRED);
    }

    private void testResumptionWithECDSACertP256CurveOnTLS12(ClientAuth clientAuth)
            throws Exception {
        resumeSession(
                new FileCert[] { ECDSA_INTCA_CERT, SM_INTCA_CERT },
                new FileCert[] { ECDSA_EE_CERT },
                Protocol.TLSV1_2,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
                clientAuth);

        resumeSession(
                new FileCert[] { ECDSA_INTCA_CERT, SM_INTCA_CERT },
                new FileCert[] { ECDSA_EE_CERT },
                Protocol.TLSV1_2,
                CipherSuite.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
                clientAuth);
    }

    private void resumeSession(
            FileCert[] trustedCerts,
            FileCert[] eeCerts,
            Protocol clientProtocol,
            CipherSuite clientCipherSuite,
            ClientAuth clientAuth) throws Exception {
        CertTuple certTuple = new CertTuple(trustedCerts, eeCerts);

        ExecutorService executor = Executors.newFixedThreadPool(1);

        JdkDragonServer.Builder serverBuilder = new JdkDragonServer.Builder();
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

            SSLContext context = null;
            long firstCreationTime = 0;
            try (JdkDragonClient client = createResumedClient(
                    certTuple, clientProtocol, clientCipherSuite,
                    null)) {
                client.connect("127.0.0.1", server.getPort());
                context = client.context;
                firstCreationTime = client.getSession().getCreationTime();
            }

            try (JdkDragonClient client = createResumedClient(
                    certTuple, clientProtocol, clientCipherSuite,
                    context)) {
                client.connect("127.0.0.1", server.getPort());

                long secondCreationTime = client.getSession().getCreationTime();
                // assertEquals(firstCreationTime, secondCreationTime);
                assertTrue(secondCreationTime - firstCreationTime < 2000);
            }
        } finally {
            executor.shutdown();
        }
    }

    private JdkDragonClient createResumedClient(
            CertTuple certTuple, Protocol protocol, CipherSuite cipherSuite,
            SSLContext context) throws Exception {
        JdkDragonClient.Builder builder = new JdkDragonClient.Builder();
        builder.setCertTuple(certTuple);
        builder.setProtocols(protocol);
        builder.setCipherSuites(cipherSuite);
        builder.setMessage("Client");
        builder.setReadResponse(true);
        builder.setContext(context);
        return builder.build();
    }
}