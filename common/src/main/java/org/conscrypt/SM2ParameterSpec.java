/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

package org.conscrypt;

import java.math.BigInteger;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

public class SM2ParameterSpec extends ECParameterSpec {
    public static final EllipticCurve CURVE = curve();
    public static final ECPoint GENERATOR = generator();
    public static final BigInteger ORDER = order();
    public static final BigInteger COFACTOR = cofactor();

    private SM2ParameterSpec() {
        super(CURVE, GENERATOR, ORDER, COFACTOR.intValue());
    }

    private static class InstanceHolder {
        private static final SM2ParameterSpec INSTANCE = new SM2ParameterSpec();
    }

    public static SM2ParameterSpec instance() {
        return InstanceHolder.INSTANCE;
    }

    public static BigInteger order() {
        return new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16);
    }

    public static ECPoint generator() {
        return new ECPoint(
                new BigInteger("32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7", 16),
                new BigInteger("BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0", 16));
    }

    public static BigInteger cofactor() {
        return BigInteger.ONE;
    }

    public static EllipticCurve curve() {
        return new EllipticCurve(
                new ECFieldFp(new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF", 16)),
                new BigInteger("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC", 16),
                new BigInteger("28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93", 16),
                null);
    }
}
