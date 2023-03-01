package com.alibaba.dragonwell.security;

import org.conscrypt.io.IoUtils;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactorySpi;
import javax.net.ssl.ManagerFactoryParameters;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;

public final class TlcpKeyManagerFactoryImpl extends KeyManagerFactorySpi {
    private static final char[] EMPTY_KEY = new char[0];

    // source of key material
    private KeyStore keyStore;

    //password
    private char[] pwd;

    /**
     * @see KeyManagerFactorySpi#engineInit(KeyStore ks, char[] password)
     */
    @Override
    protected void engineInit(KeyStore ks, char[] password)
            throws KeyStoreException, NoSuchAlgorithmException,
            UnrecoverableKeyException {
        if (ks != null) {
            keyStore = ks;
            if (password != null) {
                pwd = password.clone();
            } else {
                pwd = EMPTY_KEY;
            }
        } else {
            keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            String keyStoreName = System.getProperty("javax.net.ssl.keyStore");
            String keyStorePwd = null;
            if (keyStoreName == null || keyStoreName.equalsIgnoreCase("NONE") || keyStoreName.isEmpty()) {
                try {
                    keyStore.load(null, null);
                } catch (IOException e) {
                    throw new KeyStoreException(e);
                } catch (CertificateException e) {
                    throw new KeyStoreException(e);
                }
            } else {
                keyStorePwd = System.getProperty("javax.net.ssl.keyStorePassword");
                if (keyStorePwd == null) {
                    pwd = EMPTY_KEY;
                } else {
                    pwd = keyStorePwd.toCharArray();
                }
                FileInputStream fis = null;
                try {
                    fis = new FileInputStream(new File(keyStoreName));
                    keyStore.load(fis, pwd);
                } catch (IOException | CertificateException e) {
                    throw new KeyStoreException(e);
                } finally {
                    IoUtils.closeQuietly(fis);
                }
            }

        }

    }

    /**
     * @see KeyManagerFactorySpi#engineInit(ManagerFactoryParameters spec)
     */
    @Override
    protected void engineInit(ManagerFactoryParameters spec)
            throws InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException(
                "ManagerFactoryParameters not supported");

    }

    /**
     * @see KeyManagerFactorySpi#engineGetKeyManagers()
     */
    @Override
    protected KeyManager[] engineGetKeyManagers() {
        if (keyStore == null) {
            throw new IllegalStateException("KeyManagerFactory is not initialized");
        }
        return new KeyManager[] { new TlcpKeyManagerImpl(keyStore, pwd) };
    }
}
