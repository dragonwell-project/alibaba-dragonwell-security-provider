package com.alibaba.dragonwell.security.jce.benchmark;

import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import com.alibaba.dragonwell.security.DragonwellSecurityProvider;
import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import com.tencent.kona.KonaProvider;

public final class Utils {
    private static final Provider DRAGONWELL = new DragonwellSecurityProvider();
    private static final Provider BC = new BouncyCastleProvider();
    private static final Provider KONA = new KonaProvider();
    private static final Provider SunJCE = Security.getProvider("SunJCE");
    private static final Provider Sun = Security.getProvider("SUN");
    private static final Provider AWS_ACCP = AmazonCorrettoCryptoProvider.INSTANCE;

    private static final byte[] plainText_4096 = new byte[4096];
    private static final byte[] plainText_8192 = new byte[8192];
    private static final byte[] plainText_12288 = new byte[12288];

    static {
        new SecureRandom().nextBytes(plainText_4096);
        new SecureRandom().nextBytes(plainText_8192);
        new SecureRandom().nextBytes(plainText_12288);
    }

    public static byte[] getPlainText(String len) {
        switch (len) {
            case "4096":
                return plainText_4096;
            case "8192":
                return plainText_8192;
            case "12288":
                return plainText_12288;
            default:
                return null;
        }
    }

    public static Provider chooseProvider(String provider) {
        switch (provider) {
            case "SunJCE":
                return SunJCE;
            case "Sun":
                return Sun;    
            case "AWS_ACCP":
                return AWS_ACCP;
            case "KONA":
                return KONA;
            case "DRAGONWELL":
                return DRAGONWELL;
            case "BC":
                return BC;
            default:
                return null;
        }
    }
}
