package com.alibaba.dragonwell.security.tls.benchmark;

import com.alibaba.dragonwell.security.DragonwellSecurityProvider;
import com.tencent.kona.KonaProvider;

import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.results.format.ResultFormatType;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import javax.net.ssl.*;
import java.io.*;
import java.security.*;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

@BenchmarkMode(Mode.AverageTime)
@Warmup(iterations = 4, time = 1)
@Measurement(iterations = 5, time = 1)
@Threads(1)
@Fork(1)
@State(value = Scope.Thread)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
public class SMBenchmark {
    private static final String PROTOCOL = "TLSv1.3";
    private static final String CIPHER_SUITE = "TLS_SM4_GCM_SM3";
    private static final int MAX_PLAINTEXT_LEN = 12288;
    @Param(value = { "4096", "8192", "12288" })
    private String PlainTextLen;
    @Param(value = { "TLS_SM4_GCM_SM3" })
    private String CipherSuit;
    @Param(value = { "KONA_JSSE_SERVER", "DRAGONWELL_JSSE_SERVER" })
    private String JsseServer;

    public static void main(String[] args) throws RunnerException {
        Options opt = new OptionsBuilder()
                .include(SMBenchmark.class.getSimpleName())
                .result("dragonwell_tls_benchmark.json")
                .resultFormat(ResultFormatType.JSON).build();
        new Runner(opt).run();
    }

    @Benchmark
    public void jsseBenchMark(JsseBenchmarkContext context) throws Exception {
        implJsseBenchmark(context, JsseServer, PlainTextLen, CipherSuit);
    }

    public void implJsseBenchmark(JsseBenchmarkContext context, String jsseServer, String plainTextLen,
            String CipherSuit) throws Exception {
        switch (jsseServer) {
            case "KONA_JSSE_SERVER":
                JsseBenchmarkContext.JSSE_SERVER.KONA_JSSE_SERVER
                        .sendAndCallBackPerf(Integer.parseInt(plainTextLen));
                break;
            case "DRAGONWELL_JSSE_SERVER":
                JsseBenchmarkContext.JSSE_SERVER.DRAGONWELL_JSSE_SERVER
                        .sendAndCallBackPerf(Integer.parseInt(plainTextLen));
                break;
            default:
        }
    }

    @State(Scope.Thread)
    public static class JsseBenchmarkContext {
        private static final Provider konaProvider = new KonaProvider();
        private static final Provider dragonwellProvider = new DragonwellSecurityProvider();

        @Setup
        public void createJsseServer() throws Exception {
            Security.addProvider(konaProvider);
            System.out.println("wait for sun jsse and dragonwell jsse server start up......");
            // start sun jsse server
            new Thread(() -> {
                try {
                    JSSE_SERVER.KONA_JSSE_SERVER.startServer(PROTOCOL, konaProvider, KonaCertificateBuild.keyManagerBuilder(), KonaCertificateBuild.trustManagerBuilder());
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }).start();
            // start dragonwell jsse server
            new Thread(() -> {
                try {
                    JSSE_SERVER.DRAGONWELL_JSSE_SERVER.startServer(PROTOCOL, dragonwellProvider, CertificateBuild.keyManagerBuilder(), CertificateBuild.trustManagerBuilder());
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }).start();
            // sleep 1 seconds for waiting.
            Thread.sleep(1_000);
            // System.out.println("start up client and check data consistency......");
            JSSE_SERVER.KONA_JSSE_SERVER.startClient(PROTOCOL, konaProvider, KonaCertificateBuild.keyManagerBuilder(), KonaCertificateBuild.trustManagerBuilder());
            JSSE_SERVER.DRAGONWELL_JSSE_SERVER.startClient(PROTOCOL, dragonwellProvider, CertificateBuild.keyManagerBuilder(), CertificateBuild.trustManagerBuilder());
        }

        @TearDown
        public void destroy() throws Exception {

        }

        enum JSSE_SERVER {
            KONA_JSSE_SERVER,
            DRAGONWELL_JSSE_SERVER;

            private InputStream input;
            private OutputStream output;
            private int port;
            private byte[] data_local = new byte[MAX_PLAINTEXT_LEN];
            private byte[] data_remote = new byte[MAX_PLAINTEXT_LEN];

            private boolean dataConsistencyCheck(int len) throws Exception {
                output.write(data_local, 0, len);
                output.flush();
                int lenRec = input.read(data_remote, 0, len);
                if (lenRec != len) {
                    return false;
                }
                return Arrays.equals(data_local, data_remote);
            }

            public void startServer(String protocol, Provider provider, KeyManager[] keyManager, TrustManager[] trustManager) {
                try {
                    SSLContext sslContext = SSLContext.getInstance(protocol, provider);
                    sslContext.init(keyManager, trustManager, new SecureRandom());
                    SSLServerSocketFactory serverFactory = sslContext.getServerSocketFactory();
                    SSLServerSocket serverSocket = (SSLServerSocket) serverFactory.createServerSocket(0);
                    serverSocket.setNeedClientAuth(false);
                    port = serverSocket.getLocalPort();
                    SSLSocket sslSocket = (SSLSocket) serverSocket.accept();
                    InputStream input = new BufferedInputStream(sslSocket.getInputStream());
                    OutputStream output = new BufferedOutputStream(sslSocket.getOutputStream());
                    byte[] data = new byte[MAX_PLAINTEXT_LEN];
                    for (;;) {
                        int len = input.read(data);
                        output.write(data, 0, len);
                        output.flush();
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }

            public void startClient(String protocol, Provider provider, KeyManager[] keyManager, TrustManager[] trustManager) {
                try {
                    SSLContext sslContext = SSLContext.getInstance(protocol, provider);
                    sslContext.init(keyManager, trustManager, new SecureRandom());
                    SSLSocketFactory clientFactory = sslContext.getSocketFactory();
                    SSLSocket sslSocket = (SSLSocket) clientFactory.createSocket("localhost", port);
                    sslSocket.setEnabledCipherSuites(new String[] { CIPHER_SUITE });
                    sslSocket.startHandshake();
                    System.out.println(sslSocket.getSession().getCipherSuite());
                    input = new BufferedInputStream(sslSocket.getInputStream());
                    output = new BufferedOutputStream(sslSocket.getOutputStream());
                    new SecureRandom().nextBytes(data_local);
                    data_remote = Arrays.copyOf(data_local, data_local.length);
                    // check data consistency.
                    if (!dataConsistencyCheck(MAX_PLAINTEXT_LEN)) {
                        throw new Exception("data is not consistency!!!");
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }

            public void sendAndCallBackPerf(int len) throws Exception {
                output.write(data_local, 0, len);
                output.flush();
                // new SecureRandom().nextBytes(data_remote);
                input.read(data_remote, 0, len);
                // check data consistency.
                // for(int i = 0x0; i < len; i++) {
                // if(data_local[i] != data_remote[i]) {
                // throw new Exception("data is not consistency!!!");
                // }
                // }
            }

            public void socketShutDown() throws IOException {
                input.close();
                output.close();
            }
        }
    }
}
