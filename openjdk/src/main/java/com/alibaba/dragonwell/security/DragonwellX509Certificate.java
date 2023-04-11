/*
 * Copyright 2023 The Tongsuo Project Authors. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://github.com/Tongsuo-Project/Tongsuo/blob/master/LICENSE.txt
 */

package com.alibaba.dragonwell.security;

import org.conscrypt.OpenSSLX509Certificate;

public class DragonwellX509Certificate extends OpenSSLX509Certificate {
    private static final long serialVersionUID = 8644387307092462038L;

    DragonwellX509Certificate(long ctx) throws Exception {
        super(ctx);
    }
}
