package org.conscrypt.net.ssl.interop;

import java.io.IOException;
import java.util.Collections;

/*
 * The OpenSSL client.
 */
public class OpenSSLClient extends AbstractClient {

    private final String command;

    public OpenSSLClient(Builder builder) {
        CertTuple certTuple = builder.getCertTuple();
        FileCert caCert = (FileCert) certTuple.trustedCerts[0];
        FileCert eeCert = (FileCert) certTuple.endEntityCerts[0];

        String protocol = OpenSSLUtils.protocol(builder.getProtocol());
        String serverName = builder.getServerName();
        String alpn = Utilities.join(builder.getAppProtocols());
        String namedGroups = OpenSSLUtils.joinNamedGroups(builder.getNamedGroups());
        String signatureSchemes = OpenSSLUtils.joinSignatureSchemes(builder.getSignatureSchemes());
        String sessIn = builder.sessIn();
        String sessOut = builder.sessOut();

        command = Utilities.join(" ",
                "echo " + builder.getMessage(),
                // Wait for the server response, e.g. session ticket.
                "|", "sleep 1", "|",
                getProduct().getPath().toString(),
                "s_client",
                Utilities.DEBUG ? "-state -debug -trace" : "-quiet",
                Utilities.joinOptValue("-CAfile",
                        caCert == null ? null : caCert.certPath()),
                "-cert " + eeCert.certPath(),
                "-key " + eeCert.keyPath(),
                "-" + protocol,
                OpenSSLUtils.cipherOption(builder.getCipherSuite()),
                Utilities.joinOptValue("-servername", serverName),
                Utilities.joinOptValue("-alpn", alpn),
                Utilities.joinOptValue("-groups", namedGroups),
                Utilities.joinOptValue("-sigalgs", signatureSchemes),
                builder.isUseSessTicket() ? "" : "-no_ticket",
                Utilities.joinOptValue("-sess_in", sessIn),
                Utilities.joinOptValue("-sess_out", sessOut),
                "-no_ign_eof");
    }

    public static class Builder extends AbstractClient.Builder {

        private String sessIn;
        private String sessOut;

        public String sessIn() {
            return sessIn;
        }

        public Builder sessIn(String sessIn) {
            this.sessIn = sessIn;
            return this;
        }

        public String sessOut() {
            return sessOut;
        }

        public Builder sessOut(String sessOut) {
            this.sessOut = sessOut;
            return this;
        }

        @Override
        public OpenSSLClient build() {
            return new OpenSSLClient(this);
        }
    }

    @Override
    public Product getProduct() {
        return OpenSSL.DEFAULT;
    }

    @Override
    public void connect(String host, int port) throws IOException {
        String server = host + ":" + port;
        Process process = ProcUtils.shellProc(
                String.join(" ", command, "-connect", server),
                getLogPath(),
                Utilities.createOpensslLibEnv());
        try {
            process.waitFor();
        } catch (InterruptedException e) {
            throw new RuntimeException("Client is interrupted!", e);
        }

        if (process.exitValue() != 0) {
            throw new SSLTestException("Client exited abnormally!");
        }
    }

    @Override
    public void close() throws IOException {
        printLog();
        deleteLog();
    }
}
