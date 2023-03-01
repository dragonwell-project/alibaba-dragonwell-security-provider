/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

package com.alibaba.dragonwell.security;

import org.conscrypt.OpenSSLProvider;

public final class DragonwellSecurityProvider extends OpenSSLProvider {

    private static final String INFO = "Dragonwell JCA/JCE/JSSE native Provider, supporting RFC 8998";

    static final String NAME = "Dragonwell_Security_Provider";

    private static final double VERSION_NUM = 1.0D;

    public DragonwellSecurityProvider() {
        super(NAME, VERSION_NUM, INFO);
        put("KeyManagerFactory.TlcpKeyManagerFactory", TlcpKeyManagerFactoryImpl.class.getName());
    }
}