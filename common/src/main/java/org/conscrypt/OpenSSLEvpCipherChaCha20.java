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
import java.security.NoSuchAlgorithmException;

import javax.crypto.NoSuchPaddingException;

public class OpenSSLEvpCipherChaCha20 extends OpenSSLEvpCipher {

    public OpenSSLEvpCipherChaCha20() {}

    @Override
    String getCipherName(int keySize, Mode mode) {
        return "chacha20";
    }

    @Override
    String getBaseCipherName() {
        return "ChaCha20";
    }

    @Override
    void checkSupportedKeySize(int keySize) throws InvalidKeyException {
        if (keySize != 32) {
            throw new InvalidKeyException("Unsupported key size: " + keySize
                    + " bytes (must be 32)");
        }
    }

    @Override
    void checkSupportedMode(Mode mode) throws NoSuchAlgorithmException {
        if (mode != Mode.NONE) {
            throw new NoSuchAlgorithmException("Mode must be NONE");
        }
    }

    @Override
    void checkSupportedPadding(Padding padding) throws NoSuchPaddingException {
        if (padding != Padding.NOPADDING) {
            throw new NoSuchPaddingException("Must be NoPadding");
        }
    }

    @Override
    int getCipherBlockSize() {
        return 0;
    }

}
