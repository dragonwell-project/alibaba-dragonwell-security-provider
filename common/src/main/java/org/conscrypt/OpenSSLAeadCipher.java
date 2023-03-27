/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

package org.conscrypt;

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;

@Internal
public abstract class OpenSSLAeadCipher extends OpenSSLCipher {
    /**
     * The default tag size when one is not specified. Default to
     * full-length tags (128-bits or 16 octets).
     */
    static final int DEFAULT_TAG_SIZE_BITS = 16 * 8;

    /**
     * Keeps track of the last used block size.
     */
    private static int lastGlobalMessageSize = 32;

    /**
     * The previously used key to prevent key + nonce (IV) reuse.
     */
    private byte[] previousKey;

    /**
     * The previously used nonce (IV) to prevent key + nonce reuse.
     */
    private byte[] previousIv;

    /**
     * When set this instance must be initialized before use again. This prevents key
     * and IV reuse.
     */
    private boolean mustInitialize;

    /**
     * The byte array containing the bytes written.
     */
    byte[] buf;

    /**
     * The number of bytes written.
     */
    int bufCount;

    /**
     * AEAD cipher reference.
     */
    long evpCipher;

    /**
     * Additional authenticated data.
     */
    private byte[] aad;

    /**
     * The length of the AEAD cipher tag in bytes.
     */
    int tagLenInBytes;

    private AeadEngine engine;

    protected OpenSSLAeadCipher(Mode mode) {
        super(mode, Padding.NOPADDING);
        switch (mode) {
            case GCM:
                engine = new GCMEngine();
                break;
            case CCM:
                engine = new CCMEngine();
                break;
            default:
                break;
        }
    }

    private void checkInitialization() {
        if (mustInitialize) {
            throw new IllegalStateException(
                    "Cannot re-use same key and IV for multiple encryptions");
        }
    }

    /** Constant-time array comparison.  Since we are using this to compare keys, we want to
     * ensure there's no opportunity for a timing attack. */
    private boolean arraysAreEqual(byte[] a, byte[] b) {
        if (a.length != b.length) {
            return false;
        }

        int diff = 0;
        for (int i = 0; i < a.length; i++) {
            diff |= a[i] ^ b[i];
        }
        return diff == 0;
    }

    private void expand(int i) {
        /* Can the buffer handle i more bytes, if not expand it */
        if (bufCount + i <= buf.length) {
            return;
        }

        byte[] newbuf = new byte[(bufCount + i) * 2];
        System.arraycopy(buf, 0, newbuf, 0, bufCount);
        buf = newbuf;
    }

    private void reset() {
        aad = null;
        final int lastBufSize = lastGlobalMessageSize;
        if (buf == null) {
            buf = new byte[lastBufSize];
        } else if (bufCount > 0 && bufCount != lastBufSize) {
            lastGlobalMessageSize = bufCount;
            if (buf.length != bufCount) {
                buf = new byte[bufCount];
            }
        }
        bufCount = 0;
    }

    @Override
    void engineInitInternal(byte[] encodedKey, AlgorithmParameterSpec params,
            SecureRandom random) throws InvalidKeyException,
        InvalidAlgorithmParameterException {

        engine.setupParams(params);

        evpCipher = NativeCrypto.EVP_get_cipherbyname(getCipherName(encodedKey.length, mode));

        if (isEncrypting() && !allowsNonceReuse()) {
            if (previousKey != null && previousIv != null
                    && arraysAreEqual(previousKey, encodedKey)
                    && arraysAreEqual(previousIv, iv)) {
                mustInitialize = true;
                throw new InvalidAlgorithmParameterException(
                        "When using AEAD key and IV must not be re-used");
            }

            this.previousKey = encodedKey;
            this.previousIv = iv;
        }

        mustInitialize = false;
        reset();
}

    /**
     * Returns whether reusing nonces is allowed (aka, whether this is nonce misuse-resistant).
     * Most AEAD ciphers are not, but some are specially constructed so that reusing a key/nonce
     * pair is safe.
     */
    boolean allowsNonceReuse() {
        return false;
    }

    @Override
    int updateInternal(byte[] input, int inputOffset, int inputLen, byte[] output,
            int outputOffset, int maximumLen) throws ShortBufferException {
        checkInitialization();
        if (buf == null) {
            throw new IllegalStateException("Cipher not initialized");
        }

        ArrayUtils.checkOffsetAndCount(input.length, inputOffset, inputLen);
        if (inputLen > 0) {
            expand(inputLen);
            System.arraycopy(input, inputOffset, buf, this.bufCount, inputLen);
            this.bufCount += inputLen;
        }
        return 0;
    }

    @SuppressWarnings("LiteralClassName")
    private void throwAEADBadTagExceptionIfAvailable(String message, Throwable cause)
            throws BadPaddingException {
        Constructor<?> aeadBadTagConstructor;
        try {
            aeadBadTagConstructor = Class.forName("javax.crypto.AEADBadTagException")
                                            .getConstructor(String.class);
        } catch (Exception ignored) {
            return;
        }

        BadPaddingException badTagException = null;
        try {
            badTagException = (BadPaddingException) aeadBadTagConstructor.newInstance(message);
            badTagException.initCause(cause);
        } catch (IllegalAccessException e2) {
            // Fall through
        } catch (InstantiationException e2) {
            // Fall through
        } catch (InvocationTargetException e2) {
            throw(BadPaddingException) new BadPaddingException().initCause(
                    e2.getTargetException());
        }
        if (badTagException != null) {
            throw badTagException;
        }
    }

    @Override
    int doFinalInternal(byte[] output, int outputOffset, int maximumLen)
            throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        checkInitialization();
        final int bytesWritten;
        try {
            if (isEncrypting()) {
                bytesWritten =  engine.seal(output, outputOffset);
            } else {
                bytesWritten = engine.open(output, outputOffset);
            }
        } catch (BadPaddingException e) {
            throwAEADBadTagExceptionIfAvailable(e.getMessage(), e.getCause());
            throw e;
        }
        if (isEncrypting()) {
            mustInitialize = true;
        }
        reset();
        return bytesWritten;
    }

    @Override
    void checkSupportedPadding(Padding padding) throws NoSuchPaddingException {
        if (padding != Padding.NOPADDING) {
            throw new NoSuchPaddingException("Must be NoPadding for AEAD ciphers");
        }
    }

    @Override
    void checkSupportedMode(Mode mode) throws NoSuchAlgorithmException {
        engine.checkSupportedMode(mode);
    }

    /**
     * AEAD buffers everything until a final output.
     */
    @Override
    int getOutputSizeForUpdate(int inputLen) {
        return 0;
    }

    @Override
    int getOutputSizeForFinal(int inputLen) {
        if (isEncrypting()) {
            return bufCount + inputLen + tagLenInBytes;
        } else {
            return Math.max(0, bufCount + inputLen - tagLenInBytes);
        }
    }

    @Override
    protected void engineUpdateAAD(byte[] input, int inputOffset, int inputLen) {
        checkInitialization();
        if (aad == null) {
            aad = Arrays.copyOfRange(input, inputOffset, inputOffset + inputLen);
        } else {
            int newSize = aad.length + inputLen;
            byte[] newaad = new byte[newSize];
            System.arraycopy(aad, 0, newaad, 0, aad.length);
            System.arraycopy(input, inputOffset, newaad, aad.length, inputLen);
            aad = newaad;
        }
    }

    @Override
    protected void engineUpdateAAD(ByteBuffer buf) {
        checkInitialization();
        if (aad == null) {
            aad = new byte[buf.remaining()];
            buf.get(aad);
        } else {
            int newSize = aad.length + buf.remaining();
            byte[] newaad = new byte[newSize];
            System.arraycopy(aad, 0, newaad, 0, aad.length);
            buf.get(newaad, aad.length, buf.remaining());
            aad = newaad;
        }
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        return engine.getParameters();
    }

    protected AlgorithmParameterSpec getParameterSpec(AlgorithmParameters params)
            throws InvalidAlgorithmParameterException {
        return engine.getParameterSpec(params);
    }

    abstract String getCipherName(int keyLength, Mode mode);

    static abstract class AeadEngine {
        abstract int seal(
        byte[] out, int outOffset) throws ShortBufferException, BadPaddingException;

        abstract int open(
        byte[] out, int outOffset) throws ShortBufferException, BadPaddingException;

        abstract void setupParams(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException;

        abstract void checkSupportedMode(Mode mode) throws NoSuchAlgorithmException;

        abstract protected AlgorithmParameters getParameters();

        abstract protected AlgorithmParameterSpec getParameterSpec(AlgorithmParameters params)
                throws InvalidAlgorithmParameterException;
    }

    class GCMEngine extends AeadEngine {
        @Override
        int seal(byte[] out, int outOffset)
            throws ShortBufferException, BadPaddingException {
            return NativeCrypto.EVP_CIPHER_CTX_gcm_seal(
                evpCipher, encodedKey, iv, tagLenInBytes, out, outOffset, buf, 0, bufCount, aad);
        }

        @Override
        int open(
            byte[] out, int outOffset) throws ShortBufferException, BadPaddingException {
            return NativeCrypto.EVP_CIPHER_CTX_gcm_open(
                evpCipher, encodedKey, iv, tagLenInBytes, out, outOffset, buf, 0, bufCount, aad);
        }

        @Override
        void setupParams(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException {
            final int tagLenBits;
            final int ivLenBytes;
            if (params == null) {
                throw new InvalidAlgorithmParameterException("Aead Cipher must be initialized with params");
            } else {
                GCMParameters gcmParams = Platform.fromGCMParameterSpec(params);
                if (gcmParams == null) {
                    throw new InvalidAlgorithmParameterException("Must be GCMParameterSpec");
                } else {
                    iv = gcmParams.getIV();
                    tagLenBits = gcmParams.getTLen();
                }
            }

            if (tagLenBits < 16 || tagLenBits > 128 || tagLenBits % 8 != 0) {
                throw new InvalidAlgorithmParameterException(
                        "Tag length must be in [16, 128] and a multiple of 8; was " + tagLenBits);
            }

            ivLenBytes = iv.length;
            if (ivLenBytes < 1) {
                throw new InvalidAlgorithmParameterException(
                        "Iv length must be greater than 1 ; was " + ivLenBytes);
            }

            tagLenInBytes = tagLenBits / 8;
        }

        @Override
        void checkSupportedMode(Mode mode) throws NoSuchAlgorithmException {
            if (mode != Mode.GCM) {
                throw new NoSuchAlgorithmException("Mode must be GCM");
            }
        }

        @Override
        protected AlgorithmParameters getParameters() {
            if (iv != null && iv.length > 0) {
                try {
                    AlgorithmParameters params = AlgorithmParameters.getInstance("GCM");
                    params.init(new GCMParameterSpec(tagLenInBytes << 8, iv));
                    return params;
                } catch (NoSuchAlgorithmException | InvalidParameterSpecException e) {
                    return null;
                }
            }
            return null;
        }

        protected AlgorithmParameterSpec getParameterSpec(AlgorithmParameters params)
                throws InvalidAlgorithmParameterException {
            if (params != null) {
                try {
                    return params.getParameterSpec(GCMParameterSpec.class);
                } catch (InvalidParameterSpecException e) {
                    throw new InvalidAlgorithmParameterException(
                            "Params must be convertible to GCMParameterSpec", e);
                }
            }
            return null;
        }
    }

    class CCMEngine extends AeadEngine {
        @Override
        int seal(byte[] out, int outOffset)
            throws ShortBufferException, BadPaddingException {
            return NativeCrypto.EVP_CIPHER_CTX_ccm_seal(
                evpCipher, encodedKey, iv, tagLenInBytes, out, outOffset, buf, 0, bufCount, aad);
        }

        @Override
        int open(
            byte[] out, int outOffset) throws ShortBufferException, BadPaddingException {
            return NativeCrypto.EVP_CIPHER_CTX_ccm_open(
                evpCipher, encodedKey, iv, tagLenInBytes, out, outOffset, buf, 0, bufCount, aad);
        }

        @Override
        void setupParams(AlgorithmParameterSpec params) throws InvalidAlgorithmParameterException {
            final int tagLenBits;
            final int ivLenBytes;
            if (params == null) {
                throw new InvalidAlgorithmParameterException("Aead Cipher must be initialized with params");
            } else {
                if (!(params instanceof CCMParameterSpec)) {
                    throw new InvalidAlgorithmParameterException("Must be CCMParameterSpec");
                } else {
                    iv = ((CCMParameterSpec) params).getNonce();
                    tagLenBits = ((CCMParameterSpec) params).getIcvLen() * 8;
                }
            }

            if (tagLenBits < 32 || tagLenBits > 128 || tagLenBits % 8 != 0) {
                throw new InvalidAlgorithmParameterException(
                        "Tag length must be in [32, 128] and a multiple of 8; was " + tagLenBits);
            }

            ivLenBytes = iv.length;
            if (ivLenBytes < 7 || ivLenBytes > 13) {
                throw new InvalidAlgorithmParameterException(
                        "Iv length must be in [7, 13]; was " + ivLenBytes);
            }

            tagLenInBytes = tagLenBits / 8;
        }

        @Override
        void checkSupportedMode(Mode mode) throws NoSuchAlgorithmException {
            if (mode != Mode.CCM) {
                throw new NoSuchAlgorithmException("Mode must be CCM");
            }
        }

        @Override
        protected AlgorithmParameters getParameters() {
            if (iv != null && iv.length > 0) {
                try {
                    AlgorithmParameters params = AlgorithmParameters.getInstance("CCM");
                    params.init(new CCMParameterSpec(tagLenInBytes, iv));
                    return params;
                } catch (NoSuchAlgorithmException | InvalidParameterSpecException e) {
                    return null;
                }
            }
            return null;
        }

        protected AlgorithmParameterSpec getParameterSpec(AlgorithmParameters params)
                throws InvalidAlgorithmParameterException {
            if (params != null) {
                try {
                    return params.getParameterSpec(CCMParameterSpec.class);
                } catch (InvalidParameterSpecException e) {
                    throw new InvalidAlgorithmParameterException(
                            "Params must be convertible to CCMParameterSpec", e);
                }
            }
            return null;
        }
    }
}
