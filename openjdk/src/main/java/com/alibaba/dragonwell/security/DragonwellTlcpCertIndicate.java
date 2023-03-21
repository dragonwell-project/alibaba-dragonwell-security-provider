package com.alibaba.dragonwell.security;

public interface DragonwellTlcpCertIndicate {
    String getTlcpSignAlias();

    void setTlcpSignAlias(String alias);

    String getTlcpEncAlias();

    void setTlcpEncAlias(String alias);
}
