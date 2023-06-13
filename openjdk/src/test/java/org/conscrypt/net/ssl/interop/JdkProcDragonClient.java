/*
 * Copyright (c) 2020, Oracle and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 *
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Oracle, 500 Oracle Parkway, Redwood Shores, CA 94065 USA
 * or visit www.oracle.com if you need additional information or have any
 * questions.
 */

package org.conscrypt.net.ssl.interop;

import java.io.IOException;
import java.nio.file.Path;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

/*
 * A JDK client process.
 */
public class JdkProcDragonClient extends AbstractClient {

    private final Jdk jdk;
    private final Map<String, String> props = new HashMap<>();

    private Process process;

    public JdkProcDragonClient(Builder builder) {
        this.jdk = builder.getJdk();

        if (builder.getSecPropsFile() != null) {
            props.put(JdkProcUtils.PROP_SEC_PROPS_FILE,
                    builder.getSecPropsFile().toString());
        }

        if (builder.getCertTuple() != null) {
            props.put(JdkProcUtils.PROP_TRUSTED_CERTS,
                    JdkProcUtils.certsToStr(builder.getCertTuple().trustedCerts));
            props.put(JdkProcUtils.PROP_EE_CERTS,
                    JdkProcUtils.certsToStr(builder.getCertTuple().endEntityCerts));
        }

        if (builder.getContextProtocol() != null) {
            props.put(JdkProcUtils.PROP_CTX_PROTOCOL,
                    builder.getContextProtocol().name);
        }

        if (builder.getProtocols() != null) {
            props.put(JdkProcUtils.PROP_PROTOCOLS,
                    Utilities.join(Utilities.enumsToStrs(builder.getProtocols())));
        }

        if (builder.getCipherSuites() != null) {
            props.put(JdkProcUtils.PROP_CIPHER_SUITES,
                    Utilities.join(Utilities.enumsToStrs(builder.getCipherSuites())));
        }

        if (builder.getServerNames() != null) {
            props.put(JdkProcUtils.PROP_SERVER_NAMES,
                    Utilities.join(builder.getServerNames()));
        }

        if (builder.getAppProtocols() != null) {
            props.put(JdkProcUtils.PROP_APP_PROTOCOLS,
                    Utilities.join(builder.getAppProtocols()));
        }

        if (builder.getNamedGroups() != null) {
            props.put(JdkProcUtils.PROP_NAMED_GROUPS,
                    Utilities.join(Utilities.namedGroupsToStrs(
                            builder.getNamedGroups())));
        }

        if (builder.getSignatureSchemes() != null) {
            props.put(JdkProcUtils.PROP_SIGNATURE_SCHEMES,
                    Utilities.join(Utilities.signatureSchemesToStrs(
                            builder.getSignatureSchemes())));
        }

        if (builder.getMessage() != null) {
            props.put(JdkProcUtils.PROP_MESSAGE, builder.getMessage());
        }

        props.put(JdkProcUtils.PROP_READ_RESPONSE,
                Boolean.toString(builder.isReadResponse()));

        if (Utilities.DEBUG) {
            props.put("com.tencent.kona.ssl.debug", "all");
        }

        props.putAll(builder.getAllProps());
    }

    public static class Builder extends AbstractClient.Builder {

        private Jdk jdk = Jdk.DEFAULT;

        private Path secPropsFile;

        public Jdk getJdk() {
            return jdk;
        }

        public Builder setJdk(Jdk jdk) {
            this.jdk = jdk;
            return this;
        }

        public Path getSecPropsFile() {
            return secPropsFile;
        }

        public Builder setSecPropsFile(Path secPropsFile) {
            this.secPropsFile = secPropsFile;
            return this;
        }

        @Override
        public JdkProcDragonClient build() {
            return new JdkProcDragonClient(this);
        }
    }

    @Override
    public Jdk getProduct() {
        return jdk;
    }

    @Override
    public void connect(String host, int port) throws IOException {
        props.put(JdkProcUtils.PROP_HOST, host);
        props.put(JdkProcUtils.PROP_PORT, port + "");

        process = JdkProcUtils.java(jdk, Collections.emptyList(), getClass(),
                props, getLogPath());
        try {
            process.waitFor();
        } catch (InterruptedException e) {
            throw new RuntimeException("Client was interrupted!", e);
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

    public static void main(String[] args) throws Exception {
        Utilities.addDragonProviders();

        String trustedCertsStr = System.getProperty(JdkProcUtils.PROP_TRUSTED_CERTS);
        String eeCertsStr = System.getProperty(JdkProcUtils.PROP_EE_CERTS);

        String ctxProtocolStr = System.getProperty(JdkProcUtils.PROP_CTX_PROTOCOL);
        String protocolsStr = System.getProperty(JdkProcUtils.PROP_PROTOCOLS);
        String cipherSuitesStr = System.getProperty(JdkProcUtils.PROP_CIPHER_SUITES);

        String namedGroupsStr = System.getProperty(JdkProcUtils.PROP_NAMED_GROUPS);
        String signatureSchemesStr = System.getProperty(JdkProcUtils.PROP_SIGNATURE_SCHEMES);

        String serverNamesStr = System.getProperty(JdkProcUtils.PROP_SERVER_NAMES);
        String appProtocolsStr = System.getProperty(JdkProcUtils.PROP_APP_PROTOCOLS);

        String messageStr = System.getProperty(JdkProcUtils.PROP_MESSAGE);
        String readResponseStr = System.getProperty(JdkProcUtils.PROP_READ_RESPONSE);

        JdkDragonClient.Builder builder = new JdkDragonClient.Builder();
        builder.setCertTuple(JdkProcUtils.createCertTuple(
                trustedCertsStr, eeCertsStr));
        builder.setContextProtocol(
                ContextProtocol.contextProtocol(ctxProtocolStr));
        if (!Utilities.isEmpty(protocolsStr)) {
            builder.setProtocols(Utilities.strToEnums(
                    Protocol.class, protocolsStr));
        }
        if (!Utilities.isEmpty(cipherSuitesStr)) {
            builder.setCipherSuites(Utilities.strToEnums(
                    CipherSuite.class, cipherSuitesStr));
        }
        if (!Utilities.isEmpty(namedGroupsStr)) {
            builder.setNamedGroups(Utilities.strToEnums(
                    NamedGroup.class, namedGroupsStr));
        }
        if (!Utilities.isEmpty(signatureSchemesStr)) {
            builder.setSignatureSchemes(Utilities.strToEnums(
                    SignatureScheme.class, signatureSchemesStr));
        }
        if (!Utilities.isEmpty(serverNamesStr)) {
            builder.setServerNames(Utilities.split(serverNamesStr));
        }
        if (!Utilities.isEmpty(appProtocolsStr)) {
            builder.setAppProtocols(Utilities.split(appProtocolsStr));
        }
        if (!Utilities.isEmpty(messageStr)) {
            builder.setMessage(messageStr);
        }
        if (!Utilities.isEmpty(readResponseStr)) {
            builder.setReadResponse(Boolean.parseBoolean(readResponseStr));
        }

        String host = System.getProperty(JdkProcUtils.PROP_HOST);
        int port = Integer.getInteger(JdkProcUtils.PROP_PORT);

        try (JdkDragonClient client = builder.build()) {
            client.connect(host, port);
        }
    }
}
