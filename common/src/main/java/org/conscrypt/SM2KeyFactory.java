/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

package org.conscrypt;

import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactorySpi;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

@Internal
public class SM2KeyFactory extends KeyFactorySpi{
    public SM2KeyFactory() {}

    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec == null) {
            throw new InvalidKeySpecException("keySpec == null");
        }

        if (keySpec instanceof SM2PublicKeySpec) {
            return new SM2PublicKey((SM2PublicKeySpec) keySpec);
        } else if (keySpec instanceof X509EncodedKeySpec) {
            return OpenSSLKey.getPublicKey((X509EncodedKeySpec) keySpec, NativeConstants.EVP_PKEY_SM2);
        } else {
            throw new InvalidKeySpecException("Must use SM2PublicKeySpec or X509EncodedKeySpec; was "
                    + keySpec.getClass().getName());
        }
    }

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec == null) {
            throw new InvalidKeySpecException("keySpec == null");
        }

        if (keySpec instanceof SM2PrivateKeySpec) {
            return new SM2PrivateKey((SM2PrivateKeySpec) keySpec);
        } else if (keySpec instanceof PKCS8EncodedKeySpec) {
            return OpenSSLKey.getPrivateKey((PKCS8EncodedKeySpec) keySpec,
                    NativeConstants.EVP_PKEY_SM2);
        } else {
            throw new InvalidKeySpecException("Must use SM2PrivateKeySpec or PKCS8EncodedKeySpec; was "
                    + keySpec.getClass().getName());
        }
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec)
            throws InvalidKeySpecException {
        if (key == null) {
            throw new InvalidKeySpecException("key == null");
        }

        if (keySpec == null) {
            throw new InvalidKeySpecException("keySpec == null");
        }

        if (!"SM2".equals(key.getAlgorithm())) {
            throw new InvalidKeySpecException("Key must be an SM2 key");
        }

        if (key instanceof SM2PublicKey && SM2PublicKeySpec.class.isAssignableFrom(keySpec)) {
            SM2PublicKey sm2Key = (SM2PublicKey) key;
            @SuppressWarnings("unchecked")
            T result = (T) new SM2PublicKeySpec(sm2Key.getW());
            return result;
        } else if (key instanceof PublicKey && SM2PublicKeySpec.class.isAssignableFrom(keySpec)) {
            final byte[] encoded = key.getEncoded();
            if (!"X.509".equals(key.getFormat()) || encoded == null) {
                throw new InvalidKeySpecException("Not a valid X.509 encoding");
            }
            SM2PublicKey ecKey = (SM2PublicKey) engineGeneratePublic(new X509EncodedKeySpec(encoded));
            @SuppressWarnings("unchecked")
            T result = (T) new SM2PublicKeySpec(ecKey.getW());
            return result;
        } else if (key instanceof SM2PrivateKey && SM2PrivateKeySpec.class.isAssignableFrom(keySpec)) {
            SM2PrivateKey ecKey = (SM2PrivateKey) key;
            @SuppressWarnings("unchecked")
            T result = (T) new SM2PrivateKeySpec(ecKey.getS());
            return result;
        } else if (key instanceof PrivateKey && SM2PrivateKeySpec.class.isAssignableFrom(keySpec)) {
            final byte[] encoded = key.getEncoded();
            if (!"PKCS#8".equals(key.getFormat()) || encoded == null) {
                throw new InvalidKeySpecException("Not a valid PKCS#8 encoding");
            }
            SM2PrivateKey ecKey = (SM2PrivateKey) engineGeneratePrivate(new PKCS8EncodedKeySpec(encoded));
            @SuppressWarnings("unchecked")
            T result = (T) new SM2PrivateKeySpec(ecKey.getS());
            return result;
        } else if (key instanceof PrivateKey && PKCS8EncodedKeySpec.class.isAssignableFrom(keySpec)) {
            final byte[] encoded = key.getEncoded();
            if (!"PKCS#8".equals(key.getFormat())) {
                throw new InvalidKeySpecException("Encoding type must be PKCS#8; was "
                        + key.getFormat());
            } else if (encoded == null) {
                throw new InvalidKeySpecException("Key is not encodable");
            }
            @SuppressWarnings("unchecked") T result = (T) new PKCS8EncodedKeySpec(encoded);
            return result;
        } else if (key instanceof PublicKey && X509EncodedKeySpec.class.isAssignableFrom(keySpec)) {
            final byte[] encoded = key.getEncoded();
            if (!"X.509".equals(key.getFormat())) {
                throw new InvalidKeySpecException("Encoding type must be X.509; was "
                        + key.getFormat());
            } else if (encoded == null) {
                throw new InvalidKeySpecException("Key is not encodable");
            }
            @SuppressWarnings("unchecked") T result = (T) new X509EncodedKeySpec(encoded);
            return result;
        } else {
            throw new InvalidKeySpecException("Unsupported key type and key spec combination; key="
                    + key.getClass().getName() + ", keySpec=" + keySpec.getName());
        }
    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {
        if (key == null) {
            throw new InvalidKeyException("key == null");
        }

        if ((key instanceof SM2PublicKey) || (key instanceof SM2PrivateKey)) {
            return key;
        } else if ((key instanceof PrivateKey) && "PKCS#8".equals(key.getFormat())) {
            byte[] encoded = key.getEncoded();
            if (encoded == null) {
                throw new InvalidKeyException("Key does not support encoding");
            }
            try {
                return engineGeneratePrivate(new PKCS8EncodedKeySpec(encoded));
            } catch (InvalidKeySpecException e) {
                throw new InvalidKeyException(e);
            }
        } else if ((key instanceof PublicKey) && "X.509".equals(key.getFormat())) {
            byte[] encoded = key.getEncoded();
            if (encoded == null) {
                throw new InvalidKeyException("Key does not support encoding");
            }
            try {
                return engineGeneratePublic(new X509EncodedKeySpec(encoded));
            } catch (InvalidKeySpecException e) {
                throw new InvalidKeyException(e);
            }
        } else {
            throw new InvalidKeyException("Key must be SM2 public or private key; was "
                    + key.getClass().getName());
        }
    }
}
