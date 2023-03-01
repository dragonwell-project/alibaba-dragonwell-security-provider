/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

package org.conscrypt;

import java.security.spec.AlgorithmParameterSpec;

public class CCMParameterSpec implements AlgorithmParameterSpec {
    private byte[] nonce;
    private int icvLen;

    public CCMParameterSpec(int icvLen, byte[] src) {
        if (src == null) {
            throw new IllegalArgumentException("src array is null");
        }

        init(icvLen, src, 0, src.length);
    }

    public CCMParameterSpec(int icvLen, byte[] src, int offset, int len) {
        init(icvLen, src, offset, len);
    }

    private void init(int icvLen, byte[] src, int offset, int len) {
        if (icvLen < 0) {
            throw new IllegalArgumentException(
                "Length argument is negative");
        }
        this.icvLen = icvLen;

        if ((src == null) ||(len < 0) || (offset < 0)
                || (len > (src.length - offset))) {
            throw new IllegalArgumentException("Invalid buffer arguments");
        }

        nonce = new byte[len];
        System.arraycopy(src, offset, nonce, 0, len);
    }

    public int getIcvLen() {
        return icvLen;
    }

    public byte[] getNonce() {
        return nonce.clone();
    }
}
