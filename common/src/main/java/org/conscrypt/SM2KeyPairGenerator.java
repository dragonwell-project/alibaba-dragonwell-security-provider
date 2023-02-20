/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

package org.conscrypt;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;

@Internal
public class SM2KeyPairGenerator extends KeyPairGenerator{
    private static final String ALGORITHM = "SM2";

    private static final int KEY_SIZE = 256;

    public SM2KeyPairGenerator() {
        super(ALGORITHM);
    }

    @Override
    public KeyPair generateKeyPair() {
        final OpenSSLKey key = new OpenSSLKey(
                NativeCrypto.EC_KEY_generate_key(OpenSSLECGroupContext.getCurveByName(ALGORITHM).getNativeRef()));
        return new KeyPair(new SM2PublicKey(key), new SM2PrivateKey(key));
    }

    @Override
    public void initialize(int keysize, SecureRandom random) {
        if (keysize != KEY_SIZE) {
            throw new InvalidParameterException(
                "keySize must be 256-bit: " + keysize);
        }
    }

    @Override
    public void initialize(AlgorithmParameterSpec param, SecureRandom random) throws InvalidAlgorithmParameterException {
        if (!(param instanceof SM2ParameterSpec)) {
            throw new InvalidParameterException("params must be SM2ParameterSpec: " + param);
        }
    }
}
