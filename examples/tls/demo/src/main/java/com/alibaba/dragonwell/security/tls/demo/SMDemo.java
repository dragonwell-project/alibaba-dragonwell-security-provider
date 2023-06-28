package com.alibaba.dragonwell.security.tls.demo;

import javax.net.ssl.*;

import com.alibaba.dragonwell.security.DragonwellSecurityProvider;

import java.io.*;
import java.security.*;
import java.util.concurrent.CountDownLatch;

/**
 * tls1.3 + rfc8998 demo
 */
public class SMDemo {
    private static final String SSL_13_TYPE = "TLSv1.3";
    private static final String CIPHER_SUITE = "TLS_SM4_GCM_SM3";
    private static final String HELLO_REQUEST = "hello request";
    private static final String HELLO_RESPONSE = "hello response";

    private static volatile int port = -1;

    private static SSLContext createServerSSLContext() throws Exception {
        TrustManager[] tms = CertificateBuild.trustManagerBuilder();
        KeyManager[] kms = CertificateBuild.keyManagerBuilder();

        SSLContext sslContext = SSLContext.getInstance(SSL_13_TYPE, new DragonwellSecurityProvider());
        sslContext.init(kms, tms, new SecureRandom());
        return sslContext;
    }

    private static SSLServerSocket buildSSLServerSocket(SSLContext serverContext) throws Exception {
        SSLServerSocketFactory serverFactory = serverContext.getServerSocketFactory();
        SSLServerSocket svrSocket = (SSLServerSocket) serverFactory.createServerSocket(0);
        port = svrSocket.getLocalPort();
        svrSocket.setNeedClientAuth(false);
        return svrSocket;
    }

    private static SSLContext createClientSSLContext() throws Exception {
        TrustManager[] tms = CertificateBuild.trustManagerBuilder();
        SSLContext sslContext = SSLContext.getInstance(SSL_13_TYPE, new DragonwellSecurityProvider());
        sslContext.init(null, tms, new SecureRandom());
        return sslContext;
    }

    private static SSLSocket buildSSLClientSocket(SSLContext clientContext) throws Exception {
        SSLSocketFactory sslCntFactory = clientContext.getSocketFactory();
        SSLSocket sslSocket = (SSLSocket) sslCntFactory.createSocket("localhost", port);
        sslSocket.setEnabledCipherSuites(new String[] { CIPHER_SUITE });
        return sslSocket;
    }

    public static void main(String[] args) throws Exception {
        CountDownLatch downLatch = new CountDownLatch(1);

        // Start server asynchronously.
        SSLServerSocket serverSocket = buildSSLServerSocket(createServerSSLContext());
        Thread serverThread = new Thread(() -> {
            try {
                downLatch.countDown();
                SSLSocket sslSocket = (SSLSocket) serverSocket.accept();
                BufferedReader ioReader = new BufferedReader(new InputStreamReader(sslSocket.getInputStream()));
                PrintWriter ioWriter = new PrintWriter(sslSocket.getOutputStream());
                String tmpMsg = ioReader.readLine();
                if (tmpMsg != null) {
                    ioWriter.println(HELLO_RESPONSE);
                    ioWriter.flush();
                    System.out.println(sslSocket.getSession().getCipherSuite());
                    Thread.sleep(1_000);
                }
            } catch (Exception e) {
                e.printStackTrace();
            }
        });
        serverThread.setDaemon(true);
        serverThread.start();

        // Start client.
        downLatch.await();
        // Wait for server startup.
        Thread.sleep(2_000);
        SSLSocket clientSocket = buildSSLClientSocket(createClientSSLContext());
        BufferedReader ioReader = new BufferedReader(new InputStreamReader(
                clientSocket.getInputStream()));
        PrintWriter ioWriter = new PrintWriter(clientSocket.getOutputStream());
        ioWriter.println(HELLO_REQUEST);
        ioWriter.flush();
        System.out.println(ioReader.readLine());
        clientSocket.close();
    }
}
