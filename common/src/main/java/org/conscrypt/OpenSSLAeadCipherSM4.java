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
import java.util.Locale;

@Internal
public abstract class OpenSSLAeadCipherSM4 extends OpenSSLAeadCipher {
    private static final int SM4_BLOCK_SIZE = 16;
    private static final int SM4_KEY_SIZE = 16;

    public OpenSSLAeadCipherSM4(Mode mode) {
        super(mode);
    }

    @Override
    String getCipherName(int keyLength, Mode mode) {
        return "sm4-" + mode.toString().toLowerCase(Locale.US);
    }


    @Override
    void checkSupportedKeySize(int keyLength) throws InvalidKeyException {
        if (keyLength != SM4_KEY_SIZE) {
            throw new InvalidKeyException(
                "Unsupported key size: " + keyLength + " bytes (must be 16)");
        }
    }

    @Override
    String getBaseCipherName() {
        return "SM4";
    }

    @Override
    int getCipherBlockSize() {
        return SM4_BLOCK_SIZE;
    }

    public static class GCM extends OpenSSLAeadCipherSM4 {
        public GCM() {
            super(Mode.GCM);
        }
    }

    public static class CCM extends OpenSSLAeadCipherSM4 {
        public CCM() {
            super(Mode.CCM);
        }

    }
}
