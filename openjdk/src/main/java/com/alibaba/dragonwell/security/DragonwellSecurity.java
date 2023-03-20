package com.alibaba.dragonwell.security;

import org.conscrypt.Conscrypt;

public final class DragonwellSecurity {
    public static void setUseEngineSocketByDefault(boolean useEngineSocket) {
        Conscrypt.setUseEngineSocketByDefault(useEngineSocket);
    }
}
