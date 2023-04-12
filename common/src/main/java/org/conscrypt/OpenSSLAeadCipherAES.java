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
public abstract class OpenSSLAeadCipherAES extends OpenSSLAeadCipher {
    private static final int AES_BLOCK_SIZE = 16;

    public OpenSSLAeadCipherAES(Mode mode) {
        super(mode);
    }

    @Override
    String getCipherName(int keyLength, Mode mode) {
        return "aes-" + (keyLength * 8) + "-" + mode.toString().toLowerCase(Locale.US);
    }

    @Override
    String getBaseCipherName() {
        return "AES";
    }

    @Override
    int getCipherBlockSize() {
        return AES_BLOCK_SIZE;
    }

    public static abstract class AES_128 extends OpenSSLAeadCipherAES {
        public AES_128(Mode mode) {
            super(mode);
        }

        @Override
        void checkSupportedKeySize(int keyLength) throws InvalidKeyException {
            if (keyLength != 16) {
                throw new InvalidKeyException(
                    "Unsupported key size: " + keyLength + " bytes (must be 16)");
            }
        }

        public static class GCM extends AES_128 {
            public GCM() {
                super(Mode.GCM);
            }
        }

        public static class CCM extends AES_128 {
            public CCM() {
                super(Mode.CCM);
            }
        }
    }

    public static abstract class AES_192 extends OpenSSLAeadCipherAES {
        public AES_192(Mode mode) {
            super(mode);
        }

        @Override
        void checkSupportedKeySize(int keyLength) throws InvalidKeyException {
            if (keyLength != 24) {
                throw new InvalidKeyException(
                    "Unsupported key size: " + keyLength + " bytes (must be 24)");
            }
        }

        public static class GCM extends AES_192 {
            public GCM() {
                super(Mode.GCM);
            }
        }

        public static class CCM extends AES_192 {
            public CCM() {
                super(Mode.CCM);
            }
        }
    }

    public static abstract class AES_256 extends OpenSSLAeadCipherAES {
        public AES_256(Mode mode) {
            super(mode);
        }

        @Override
        void checkSupportedKeySize(int keyLength) throws InvalidKeyException {
            if (keyLength != 32) {
                throw new InvalidKeyException(
                    "Unsupported key size: " + keyLength + " bytes (must be 32)");
            }
        }

        public static class GCM extends AES_256 {
            public GCM() {
                super(Mode.GCM);
            }
        }

        public static class CCM extends AES_256 {
            public CCM() {
                super(Mode.CCM);
            }
        }
    }
}
