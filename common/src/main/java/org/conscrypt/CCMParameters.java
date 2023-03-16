/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

package org.conscrypt;

import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;

@Internal
public final class CCMParameters extends AlgorithmParametersSpi {

    // The default value (in bits) for TLEN in the CCM ASN.1 module
    private static final int DEFAULT_ICVLEN = 96;

    /** The icvlen length in bits. */
    private int icvLen;

    private byte[] nonce;

    public CCMParameters(int icvLen, byte[] nonce) {
        this.icvLen = icvLen;
        this.nonce = nonce;
    }

    int getIcvLen() {
        return icvLen;
    }

    byte[] getNonce() {
        return nonce.clone();
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec algorithmParameterSpec)
            throws InvalidParameterSpecException {
        if (algorithmParameterSpec instanceof CCMParameterSpec) {
            this.icvLen = ((CCMParameterSpec) algorithmParameterSpec).getIcvLen();
            this.nonce = ((CCMParameterSpec) algorithmParameterSpec).getNonce();
        } else {
            throw new InvalidParameterSpecException("Only CCMParameterSpec is supported");
        }
    }

    @Override
    protected void engineInit(byte[] bytes) throws IOException {
        long readRef = 0;
        long seqRef = 0;
        try {
            readRef = NativeCrypto.asn1_read_init(bytes);
            seqRef = NativeCrypto.asn1_read_sequence(readRef);
            byte[] newNonce = NativeCrypto.asn1_read_octetstring(seqRef);
            int newIcvLen = DEFAULT_ICVLEN;
            if (!NativeCrypto.asn1_read_is_empty(seqRef)) {
                newIcvLen = 8 * (int) NativeCrypto.asn1_read_uint64(seqRef);
            }
            if (!NativeCrypto.asn1_read_is_empty(seqRef)
                    || !NativeCrypto.asn1_read_is_empty(readRef)) {
                throw new IOException("Error reading ASN.1 encoding");
            }
            this.nonce = newNonce;
            this.icvLen = newIcvLen;
        } finally {
            NativeCrypto.asn1_read_free(seqRef);
            NativeCrypto.asn1_read_free(readRef);
        }
    }

    @Override
    protected void engineInit(byte[] bytes, String format) throws IOException {
        if ((format == null) || format.equals("ASN.1")) {
            engineInit(bytes);
        } else {
            throw new IOException("Unsupported format: " + format);
        }
    }

    @Override
    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> aClass)
            throws InvalidParameterSpecException {
        if ((aClass != null) && aClass.getName().equals("org.conscrypt.CCMParameterSpec")) {
            return aClass.cast(new CCMParameterSpec(icvLen, nonce));
        } else {
            throw new InvalidParameterSpecException("Unsupported class: " + aClass);
        }
    }

    @Override
    protected byte[] engineGetEncoded() throws IOException {
        long cbbRef = 0;
        long seqRef = 0;
        try {
            cbbRef = NativeCrypto.asn1_write_init();
            seqRef = NativeCrypto.asn1_write_sequence(cbbRef);
            NativeCrypto.asn1_write_octetstring(seqRef, this.nonce);
            if (this.icvLen != DEFAULT_ICVLEN) {
                NativeCrypto.asn1_write_uint64(seqRef, this.icvLen / 8);
            }
            return NativeCrypto.asn1_write_finish(cbbRef);
        } catch (IOException e) {
            NativeCrypto.asn1_write_cleanup(cbbRef);
            throw e;
        } finally {
            NativeCrypto.asn1_write_free(seqRef);
            NativeCrypto.asn1_write_free(cbbRef);
        }
    }

    @Override
    protected byte[] engineGetEncoded(String format) throws IOException {
        if ((format == null) || format.equals("ASN.1")) {
            return engineGetEncoded();
        }
        throw new IOException("Unsupported format: " + format);
    }

    @Override
    protected String engineToString() {
        return "Tongsuo CCM AlgorithmParameters";
    }
}
