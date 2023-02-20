/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

package org.conscrypt;

import java.io.ByteArrayOutputStream;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Locale;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

@Internal
public class SM2Cipher extends CipherSpi {
    /**
     * The current OpenSSL key we're operating on.
     */
    OpenSSLKey key;

    /**
     * Current cipher mode: encrypting or decrypting.
     */
    boolean encrypting;

    /**
     * Buffer for operations
     */
    private Buffer buffer = new Buffer();

    private NativeRef.EVP_PKEY_CTX pkeyCtx;

    @Override
    protected void engineSetMode(String mode) throws NoSuchAlgorithmException {
        final String modeUpper = mode.toUpperCase(Locale.ROOT);
        if (!"NONE".equals(modeUpper)) {
            throw new NoSuchAlgorithmException("mode not supported: " + mode);
        }
    }

    @Override
    protected void engineSetPadding(String padding) throws NoSuchPaddingException {
        final String paddingUpper = padding.toUpperCase(Locale.ROOT);
        if (!"NOPADDING".equals(paddingUpper)) {
            throw new NoSuchPaddingException("padding not supported: " + padding);
        }
    }

    @Override
    protected int engineGetBlockSize() {
        return 0;
    }

    private int derSize(int length) {
        int ret = 2;
        if (length > 127) {
            int tmplen = length;
            while (tmplen > 0) {
                tmplen >>= 8;
                ret++;
            }
        }
        return ret + length;
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        int totalLen = buffer.size() + inputLen;
        if (encrypting) {
            // derSize(C1) <= 35, derSize(C3) = 34
            return derSize(2 * 35 + 34 + derSize(totalLen));
        } else {
            // 2(s) for TL(s) bytes in der's TLV triplet, derSize(INT) >= 3
            return totalLen - 2 - 34 - 2 * 3 - 2;
        }
    }

    @Override
    protected byte[] engineGetIV() {
        return null;
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return null;
    }

    void engineInitInternal(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        if (opmode == Cipher.ENCRYPT_MODE || opmode == Cipher.WRAP_MODE) {
            encrypting = true;
            if (key instanceof SM2PublicKey) {
                this.key = ((SM2PublicKey) key).getOpenSSLKey();
            } else {
                throw new InvalidKeyException(
                        "Need SM2PublicKey");
            }
        } else if (opmode == Cipher.DECRYPT_MODE || opmode == Cipher.UNWRAP_MODE) {
            encrypting = false;
            if (key instanceof SM2PrivateKey) {
                this.key = ((SM2PrivateKey) key).getOpenSSLKey();
            } else {
                throw new InvalidKeyException(
                        "Need SM2PrivateKey");
            }
        } else {
            throw new InvalidParameterException("Unsupported opmode " + opmode);
        }

        buffer.reset();
        pkeyCtx = new NativeRef.EVP_PKEY_CTX(encrypting
                        ? NativeCrypto.EVP_PKEY_encrypt_init(this.key.getNativeRef())
                        : NativeCrypto.EVP_PKEY_decrypt_init(this.key.getNativeRef()));
    }

    @Override
    protected int engineGetKeySize(Key key) throws InvalidKeyException {
        if (key instanceof SM2PrivateKey || key instanceof SM2PublicKey) {
            return 256;
        }
        throw new InvalidKeyException("Need SM2 private or public key");
    }

    @Override
    protected void engineInit(int opmode, Key key, SecureRandom random) throws InvalidKeyException {
        engineInitInternal(opmode, key, random);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameterSpec params,
            SecureRandom random) throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException("unknown param type: "
                    + params.getClass().getName());
        }

        engineInitInternal(opmode, key, random);
    }

    @Override
    protected void engineInit(int opmode, Key key, AlgorithmParameters params, SecureRandom random)
            throws InvalidKeyException, InvalidAlgorithmParameterException {
        if (params != null) {
            throw new InvalidAlgorithmParameterException("unknown param type: "
                    + params.getClass().getName());
        }

        engineInitInternal(opmode, key, random);
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inputOffset, int inputLen) {
        buffer.write(input, inputOffset, inputLen);
        return EmptyArray.BYTE;
    }

    @Override
    protected int engineUpdate(byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset) throws ShortBufferException {
        buffer.write(input, inputOffset, inputLen);
        return 0;
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inputOffset, int inputLen)
            throws IllegalBlockSizeException, BadPaddingException {
        if (input != null) {
            engineUpdate(input, inputOffset, inputLen);
        }

        byte[] output = new byte[engineGetOutputSize(buffer.size())];
        int resultSize = 0;
        if (encrypting) {
            resultSize = NativeCrypto.EVP_PKEY_encrypt(pkeyCtx, output, 0, buffer.toByteArray(), 0, buffer.size());
        } else {
            resultSize = NativeCrypto.EVP_PKEY_decrypt(pkeyCtx, output, 0, buffer.toByteArray(), 0, buffer.size());
        }
        if (resultSize != output.length) {
            output = Arrays.copyOf(output, resultSize);
        }

        buffer.reset();
        return output;
    }

    @Override
    protected int engineDoFinal(byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset) throws ShortBufferException, IllegalBlockSizeException,
            BadPaddingException {
        byte[] b = engineDoFinal(input, inputOffset, inputLen);

        final int lastOffset = outputOffset + b.length;
        if (lastOffset > output.length) {
            throw new ShortBufferWithoutStackTraceException("output buffer is too small " + output.length + " < "
                    + lastOffset);
        }

        System.arraycopy(b, 0, output, outputOffset, b.length);
        return b.length;
    }

    @Override
    protected byte[] engineWrap(Key key) throws IllegalBlockSizeException, InvalidKeyException {
        try {
            byte[] encoded = key.getEncoded();
            return engineDoFinal(encoded, 0, encoded.length);
        } catch (BadPaddingException e) {
            IllegalBlockSizeException newE = new IllegalBlockSizeException();
            newE.initCause(e);
            throw newE;
        }
    }

    @Override
    protected Key engineUnwrap(byte[] wrappedKey, String wrappedKeyAlgorithm,
            int wrappedKeyType) throws InvalidKeyException, NoSuchAlgorithmException {
        try {
            byte[] encoded = engineDoFinal(wrappedKey, 0, wrappedKey.length);
            if (wrappedKeyType == Cipher.PUBLIC_KEY) {
                KeyFactory keyFactory = KeyFactory.getInstance(wrappedKeyAlgorithm);
                return keyFactory.generatePublic(new X509EncodedKeySpec(encoded));
            } else if (wrappedKeyType == Cipher.PRIVATE_KEY) {
                KeyFactory keyFactory = KeyFactory.getInstance(wrappedKeyAlgorithm);
                return keyFactory.generatePrivate(new PKCS8EncodedKeySpec(encoded));
            } else if (wrappedKeyType == Cipher.SECRET_KEY) {
                return new SecretKeySpec(encoded, wrappedKeyAlgorithm);
            } else {
                throw new UnsupportedOperationException("wrappedKeyType == " + wrappedKeyType);
            }
        } catch (IllegalBlockSizeException | BadPaddingException | InvalidKeySpecException e) {
            throw new InvalidKeyException(e);
        }
    }

    private static final class Buffer extends ByteArrayOutputStream {

        public void reset() {
            Arrays.fill(buf, (byte)0);
            super.reset();
        }
    }
}
