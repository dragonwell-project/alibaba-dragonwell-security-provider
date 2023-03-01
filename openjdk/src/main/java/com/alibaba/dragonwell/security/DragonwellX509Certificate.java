package com.alibaba.dragonwell.security;

import org.conscrypt.OpenSSLX509Certificate;

public final class DragonwellX509Certificate extends OpenSSLX509Certificate {
    public DragonwellX509Certificate(long ctx) throws Exception {
        super(ctx);
    }
}
