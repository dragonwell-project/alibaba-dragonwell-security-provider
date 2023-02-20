/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

package org.conscrypt.java.security;

import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.List;

import org.conscrypt.SM2PrivateKeySpec;
import org.conscrypt.SM2PublicKeySpec;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;
import tests.util.ServiceTester;

@RunWith(JUnit4.class)
public class KeyFactoryTestSM2 extends
    AbstractKeyFactoryTest<SM2PublicKeySpec, SM2PrivateKeySpec> {

  public KeyFactoryTestSM2() {
    super("SM2", SM2PublicKeySpec.class, SM2PrivateKeySpec.class);
  }

  @Override
  public ServiceTester customizeTester(ServiceTester tester) {
    // BC's EC keys always use explicit params, even though it's a bad idea, and we don't support
    // those, so don't test BC keys
    return tester.skipProvider("BC");
  }

  @Override
  protected void check(KeyPair keyPair) throws Exception {
    new SignatureHelper("SM3withSM2").test(keyPair);
  }

  @Override
  protected List<KeyPair> getKeys() throws NoSuchAlgorithmException, InvalidKeySpecException {
    return Arrays.asList(
        new KeyPair(
            DefaultKeys.getPublicKey("SM2"),
            DefaultKeys.getPrivateKey("SM2")
        ),
        new KeyPair(
            new TestPublicKey(DefaultKeys.getPublicKey("SM2")),
            new TestPrivateKey(DefaultKeys.getPrivateKey("SM2"))
        ),
        new KeyPair(
            new TestECPublicKey((ECPublicKey)DefaultKeys.getPublicKey("SM2")),
            new TestECPrivateKey((ECPrivateKey)DefaultKeys.getPrivateKey("SM2"))
        )
    );
  }
}
