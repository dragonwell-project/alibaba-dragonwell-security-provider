package com.alibaba.dragonwell.security.jce.benchmark;

import java.security.Provider;
import java.util.concurrent.TimeUnit;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;
import org.openjdk.jmh.results.format.ResultFormatType;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import com.alibaba.dragonwell.security.DragonwellSecurityProvider;
import com.amazon.corretto.crypto.provider.AmazonCorrettoCryptoProvider;
import com.tencent.kona.KonaProvider;

@BenchmarkMode(Mode.AverageTime)
@Warmup(iterations = 6, time = 1)
@Measurement(iterations = 6, time = 1)
@Threads(1)
@Fork(1)
@State(value = Scope.Thread)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
public class MacBenchmark {
    private static final String HMAC_SHA256_ALGORITHM = "HmacSHA256";
    private static final String HMAC_SHA384_ALGORITHM = "HmacSHA384";
    private static final String HMAC_SHA512_ALGORITHM = "HmacSHA512";
    public static final int AES_KEY_SIZE = 128;

    @Param(value = { HMAC_SHA256_ALGORITHM, HMAC_SHA384_ALGORITHM, HMAC_SHA512_ALGORITHM })
    private String MacAlgorithm;
    @Param(value = { "4096", "8192", "12288" })
    private String PlainTextLength;
    @Param(value = { "DRAGONWELL", "BC", "SunJCE" })
    private String Provider;

    public static void main(String[] args) throws RunnerException {
        Options opt = new OptionsBuilder()
                .include(MacBenchmark.class.getSimpleName())
                .result("dragonwell_mac_benchmark.json")
                .resultFormat(ResultFormatType.JSON).build();
        new Runner(opt).run();
    }

    private byte[] digest(MacBenchmark.MacBenchmarkContext context, String provider, String len, String algo) throws Exception {
        Mac mac = Mac.getInstance(algo, context.chooseProvider(provider));
        mac.init(context.getSecretKeySpec(algo));
        return mac.doFinal(context.getPlainText(len));
    }

    @Benchmark
    public void macDigestBenchMark(MacBenchmark.MacBenchmarkContext context, Blackhole blackhole) throws Exception {
        blackhole.consume(digest(context, Provider, PlainTextLength, MacAlgorithm));
    }

    @State(Scope.Thread)
    public static class MacBenchmarkContext {
        private SecretKeySpec Secret_Key_Spec_256 = null;
        private SecretKeySpec Secret_Key_Spec_384 = null;
        private SecretKeySpec Secret_Key_Spec_512 = null;

        private void initMacContext() throws Exception {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(AES_KEY_SIZE);
            Secret_Key_Spec_256 = new SecretKeySpec(keyGenerator.generateKey().getEncoded(), HMAC_SHA256_ALGORITHM);
            Secret_Key_Spec_384 = new SecretKeySpec(keyGenerator.generateKey().getEncoded(), HMAC_SHA384_ALGORITHM);
            Secret_Key_Spec_512 = new SecretKeySpec(keyGenerator.generateKey().getEncoded(), HMAC_SHA512_ALGORITHM);
        }

        @Setup
        public void createMacContext() throws Exception {
            initMacContext();
        }

        public SecretKeySpec getSecretKeySpec(String algo) {
            switch (algo) {
                case HMAC_SHA256_ALGORITHM:
                    return Secret_Key_Spec_256;
                case HMAC_SHA384_ALGORITHM:
                    return Secret_Key_Spec_384;
                case HMAC_SHA512_ALGORITHM:
                    return Secret_Key_Spec_512;
                default:
                    return null;
            }
        }

        public byte[] getPlainText(String len) {
            return Utils.getPlainText(len);        
        }

        public Provider chooseProvider(String provider) {
            return Utils.chooseProvider(provider);
        }
    }
}
