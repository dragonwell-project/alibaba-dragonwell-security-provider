package org.conscrypt;

import org.eclipse.jetty.client.HttpClient;
import org.eclipse.jetty.client.api.ContentResponse;
import org.eclipse.jetty.http.HttpVersion;
import org.eclipse.jetty.server.HttpConfiguration;
import org.eclipse.jetty.server.HttpConnectionFactory;
import org.eclipse.jetty.server.SecureRequestCustomizer;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.server.SslConnectionFactory;
import org.eclipse.jetty.server.handler.DefaultHandler;
import org.eclipse.jetty.server.handler.HandlerList;
import org.eclipse.jetty.servlet.ServletContextHandler;
import org.eclipse.jetty.util.ssl.SslContextFactory;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import static org.conscrypt.TestUtils.readSM2PrivateKeyPemFile;
import static org.conscrypt.TestUtils.openTestFile;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.junit.Test;
import static org.junit.Assert.assertEquals;

public class TestTLSWithJetty {
    private static final char[] EMPTY_PASSWORD = new char[0];

    @Test
    public void test_TLS13_SM() throws Exception {
        Server server = createServer();
        server.start();
        int port = server.getURI().getPort();

        HttpClient client = createClient();
        client.start();

        // Access Servlet /hello over HTTPS scheme.
        ContentResponse response = client.GET(
                new URI(String.format("https://localhost:%d/hello", port)));
        client.stop();
        server.stop();
        assertEquals(response.getContentAsString(), "Hello!\n");
    }

    private static Server createServer() throws Exception {
        SslContextFactory.Server sslContextFactory = new SslContextFactory.Server();
        sslContextFactory.setSslContext(createContext());

        HttpConfiguration config = new HttpConfiguration();
        config.setSecureScheme("https");
        config.addCustomizer(new SecureRequestCustomizer());

        Server server = new Server();
        ServerConnector httpsConnector = new ServerConnector(server,
                new SslConnectionFactory(sslContextFactory,
                        HttpVersion.HTTP_1_1.asString()),
                new HttpConnectionFactory(config));
        httpsConnector.setPort(0);
        server.addConnector(httpsConnector);

        ServletContextHandler context = new ServletContextHandler();
        context.setContextPath("/");
        context.addServlet(HelloServlet.class, "/hello");
        server.setHandler(new HandlerList(context, new DefaultHandler()));

        return server;
    }

    // Create Jetty client, which supports TLS connection.
    private static HttpClient createClient() throws Exception {
        SslContextFactory.Client sslContextFactory = new SslContextFactory.Client();
        sslContextFactory.setSslContext(createContext());

        HttpClient httpClient = new HttpClient(sslContextFactory);
        return httpClient;
    }

    private static SSLContext createContext() throws Exception {
        KeyStore keyStore = buildKeyStoreForShangMi("self_sign_sm2_cert/sm2.crt",
                "self_sign_sm2_cert/sm2PriKeyPkcs8.key");
        SSLContext sslContext = SSLContext.getInstance("TLSv1.3", Conscrypt.newProvider());

        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(keyStore, EMPTY_PASSWORD);

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(keyStore);

        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), new SecureRandom());
        return sslContext;
    }

    private static KeyStore buildKeyStoreForShangMi(String cert, String key) throws Exception {
        X509Certificate selfSignCert = OpenSSLX509Certificate.fromX509PemInputStream(openTestFile(cert));
        PrivateKey privateKey = readSM2PrivateKeyPemFile(key);

        // Build Certification Chain
        X509Certificate[] chain = new X509Certificate[] { selfSignCert };
        KeyStore ks = KeyStore.getInstance("PKCS12", new BouncyCastleProvider());
        ks.load(null);
        ks.setKeyEntry("tls-ee-demo", privateKey, EMPTY_PASSWORD, chain);
        ks.setCertificateEntry("tls-trust-demo", selfSignCert);
        return ks;
    }

    public static class HelloServlet extends HttpServlet {

        private static final long serialVersionUID = -4748362333014218314L;

        @Override
        public void doGet(
                HttpServletRequest request, HttpServletResponse response)
                throws ServletException, IOException {
            response.setContentType("text/plain");
            response.setStatus(HttpServletResponse.SC_OK);
            response.getWriter().println("Hello!");
        }

        @Override
        public void doPost(
                HttpServletRequest request, HttpServletResponse response)
                throws ServletException, IOException {
            doGet(request, response);
        }
    }
}
