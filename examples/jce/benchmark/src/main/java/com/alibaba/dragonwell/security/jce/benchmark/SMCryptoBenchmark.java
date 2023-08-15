package com.alibaba.dragonwell.security.jce.benchmark;

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

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

@BenchmarkMode(Mode.AverageTime)
@Warmup(iterations = 6, time = 1)
@Measurement(iterations = 6, time = 1)
@Threads(1)
@Fork(1)
@State(value = Scope.Thread)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
public class SMCryptoBenchmark {
    public static final int AES_KEY_SIZE = 128;
    public static final int GCM_IV_LENGTH = 12;

    @Param(value = { "SM4/GCM/NoPadding", "AES/GCM/NoPadding" })
    private String CryptoAlgorithm;
    @Param(value = { "4096", "8192", "12288" })
    private String PlainTextLength;
    @Param(value = { "DRAGONWELL", "BC", "KONA", "SunJCE", "AWS_ACCP" })
    private String Provider;

    public static void main(String[] args) throws RunnerException {
        Options opt = new OptionsBuilder()
                .include(SMCryptoBenchmark.class.getSimpleName())
                .result("dragonwell_jce_benchmark.json")
                .resultFormat(ResultFormatType.JSON).build();
        new Runner(opt).run();
    }

    public static byte[] crypto(int mode, SMCryptoBenchmark.JceBenchmarkContext context, String provider, String len,
            String algo)
            throws Exception {
        // Get Cipher Instance
        Cipher cipher = Cipher.getInstance(algo, context.chooseProvider(provider));
        // Initialize Cipher for ENCRYPT_MODE
        cipher.init(mode, context.getSecretKeySpec(algo), context.getSecretParamSpec(algo));
        // Perform Encryption
        byte[] data = null;
        if (mode == Cipher.ENCRYPT_MODE) {
            data = context.getPlainText(len);
        } else if (mode == Cipher.DECRYPT_MODE) {
            data = context.getCipherText(len, algo);
        }
        return cipher.doFinal(data);
    }

    @Benchmark
    public void jceEncryptBenchMark(SMCryptoBenchmark.JceBenchmarkContext context, Blackhole blackhole) throws Exception {
        if ((Provider.equals("KONA") || Provider.equals("AWS_ACCP")) && CryptoAlgorithm.equals("AES/GCM/NoPadding")) {
            return;
        }
        if ((Provider.equals("SunJCE") || Provider.equals("AWS_ACCP")) && CryptoAlgorithm.equals("SM4/GCM/NoPadding")) {
            return;
        }
        byte[] cipherText = crypto(Cipher.ENCRYPT_MODE, context, Provider, PlainTextLength, CryptoAlgorithm);
        blackhole.consume(cipherText);
        // if (!context.checkCipherTextDataConsistency(cipherText, PlainTextLength, CryptoAlgorithm)) {
        //     throw new Exception("Data is not consistency");
        // }
    }

    // @Benchmark
    public void jceDecryptBenchMark(SMCryptoBenchmark.JceBenchmarkContext context, Blackhole blackhole) throws Exception {
        byte[] plainText = crypto(Cipher.DECRYPT_MODE, context, Provider, PlainTextLength, CryptoAlgorithm);
        blackhole.consume(plainText);
        // if (!context.checkPlainTextDataConsistency(plainText, PlainTextLength)) {
        // throw new Exception("Data is not consistency");
        // }
    }

    @State(Scope.Thread)
    public static class JceBenchmarkContext {
        private SecretKeySpec SM4_GCM_Key_Spec = null;
        private GCMParameterSpec SM4_GCM_Param_Spec = null;
        private SecretKeySpec AES_GCM_Key_Spec = null;
        private GCMParameterSpec AES_GCM_Param_Spec = null;
        private byte[] cipherText_sm4_4096 = null;
        private byte[] cipherText_sm4_8192 = null;
        private byte[] cipherText_sm4_12288 = null;
        private byte[] cipherText_aes_4096 = null;
        private byte[] cipherText_aes_8192 = null;
        private byte[] cipherText_aes_12288 = null;

        private void initSM4Context() {
            byte[] key = new byte[16];
            byte[] IV = new byte[12];
            new SecureRandom().nextBytes(key);
            new SecureRandom().nextBytes(IV);
            SM4_GCM_Key_Spec = new SecretKeySpec(key, "SM4");
            SM4_GCM_Param_Spec = new GCMParameterSpec(GCM_IV_LENGTH * 8, IV);
        }

        private void initAESContext() throws Exception {
            KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
            keyGenerator.init(AES_KEY_SIZE);
            byte[] IV = new byte[GCM_IV_LENGTH];
            new SecureRandom().nextBytes(IV);
            AES_GCM_Key_Spec = new SecretKeySpec(keyGenerator.generateKey().getEncoded(), "AES");
            AES_GCM_Param_Spec = new GCMParameterSpec(GCM_IV_LENGTH * 8, IV);
        }

        private void initPlainCipherText() throws Exception {
            cipherText_aes_4096 = initEncrypt(Utils.getPlainText("4096"), "AES/GCM/NoPadding", AES_GCM_Key_Spec,
                    AES_GCM_Param_Spec);
            cipherText_aes_8192 = initEncrypt(Utils.getPlainText("8192"), "AES/GCM/NoPadding", AES_GCM_Key_Spec,
                    AES_GCM_Param_Spec);
            cipherText_aes_12288 = initEncrypt(Utils.getPlainText("12288"), "AES/GCM/NoPadding", AES_GCM_Key_Spec,
                    AES_GCM_Param_Spec);
            cipherText_sm4_4096 = initEncrypt(Utils.getPlainText("4096"), "SM4/GCM/NoPadding", SM4_GCM_Key_Spec,
                    SM4_GCM_Param_Spec);
            cipherText_sm4_8192 = initEncrypt(Utils.getPlainText("8192"), "SM4/GCM/NoPadding", SM4_GCM_Key_Spec,
                    SM4_GCM_Param_Spec);
            cipherText_sm4_12288 = initEncrypt(Utils.getPlainText("12288"), "SM4/GCM/NoPadding", SM4_GCM_Key_Spec,
                    SM4_GCM_Param_Spec);
        }

        private byte[] initEncrypt(byte[] plainText, String algo, SecretKeySpec keySpec,
                GCMParameterSpec gcmParameterSpec) throws Exception {
            // Get Cipher Instance
            Cipher cipher = Cipher.getInstance(algo, new DragonwellSecurityProvider());
            // Initialize Cipher for ENCRYPT_MODE
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);
            // Perform Encryption
            return cipher.doFinal(plainText);
        }

        @Setup
        public void createJceContext() throws Exception {
            initSM4Context();
            initAESContext();
            initPlainCipherText();
        }

        public SecretKeySpec getSecretKeySpec(String algo) {
            switch (algo) {
                case "AES/GCM/NoPadding":
                    return AES_GCM_Key_Spec;
                case "SM4/GCM/NoPadding":
                    return SM4_GCM_Key_Spec;
                default:
                    return null;
            }
        }

        public GCMParameterSpec getSecretParamSpec(String algo) {
            switch (algo) {
                case "AES/GCM/NoPadding":
                    return AES_GCM_Param_Spec;
                case "SM4/GCM/NoPadding":
                    return SM4_GCM_Param_Spec;
                default:
                    return null;
            }
        }

        public byte[] getCipherText(String len, String algo) throws Exception {
            if ("AES/GCM/NoPadding".equals(algo) && "4096".equals(len)) {
                return cipherText_aes_4096;
            } else if ("AES/GCM/NoPadding".equals(algo) && "8192".equals(len)) {
                return cipherText_aes_8192;
            } else if ("AES/GCM/NoPadding".equals(algo) && "12288".equals(len)) {
                return cipherText_aes_12288;
            } else if ("SM4/GCM/NoPadding".equals(algo) && "4096".equals(len)) {
                return cipherText_sm4_4096;
            } else if ("SM4/GCM/NoPadding".equals(algo) && "8192".equals(len)) {
                return cipherText_sm4_8192;
            } else if ("SM4/GCM/NoPadding".equals(algo) && "12288".equals(len)) {
                return cipherText_sm4_12288;
            } else {
                throw new Exception("Unknow algo and length");
            }
        }

        public boolean checkPlainTextDataConsistency(byte[] plainText, String len) {
            switch (len) {
                case "4096":
                    return Arrays.equals(plainText, Utils.getPlainText("4096"));
                case "8192":
                    return Arrays.equals(plainText, Utils.getPlainText("8192"));
                case "12288":
                    return Arrays.equals(plainText, Utils.getPlainText("12288"));
                default:
                    return false;
            }
        }

        public byte[] getPlainText(String len) {
            return Utils.getPlainText(len);        
        }

        public boolean checkCipherTextDataConsistency(byte[] CipherText, String len, String algo) throws Exception {
            return Arrays.equals(CipherText, getCipherText(len, algo));
        }

        public Provider chooseProvider(String provider) {
            return Utils.chooseProvider(provider);
        }
    }
}
