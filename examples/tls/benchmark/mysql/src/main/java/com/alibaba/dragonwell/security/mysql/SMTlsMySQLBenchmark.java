package com.alibaba.dragonwell.security.mysql;

import java.security.Security;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.FileOutputStream;
import java.io.File;
import java.util.concurrent.TimeUnit;

import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;
import org.openjdk.jmh.results.format.ResultFormatType;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import com.mysql.cj.jdbc.MysqlDataSource;
import com.tencent.kona.KonaProvider;
import com.alibaba.dragonwell.security.DragonwellSecurityProvider;

@BenchmarkMode(Mode.AverageTime)
@Warmup(iterations = 6, time = 1)
@Measurement(iterations = 6, time = 1)
@Threads(1)
@Fork(1)
@State(value = Scope.Thread)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
public class SMTlsMySQLBenchmark {
    private final static String DRAGONWELL = "Dragonwell";
    private final static String KONA = "Kona";
    private final static String PROVIDER = System.getProperty("Provider");

    public static void main(String[] args) throws RunnerException {
        Options opt = new OptionsBuilder()
                .include(SMTlsMySQLBenchmark.class.getSimpleName())
                .result("mysql_sm4_security_provider_benchmark.json")
                .resultFormat(ResultFormatType.JSON).build();
        new Runner(opt).run();
    }

    @Benchmark
    public void smTlsMySQLBenchMark(SMTlsMySQLBenchmark.BenchmarkContext context, Blackhole blackhole) throws Exception {
        String IMAGE_DATA = "image_data";
        ResultSet resultSet = context.getPreparedStatement().executeQuery();
        blackhole.consume(resultSet);
        resultSet.close();
    }

    @State(Scope.Thread)
    public static class BenchmarkContext {
        private final String USER = "root";
        private final String HOST_NAME = "127.0.0.1";
        private final String JKS_PASSWORD = "123456";
        private final String SQL_PASSWORD = "Wsj.123456";
        private final String DATA_BASE = "IMAGES";
        private final String DATA_TABLE = "images_table";
        private final String SQL = "SELECT image_data FROM images_table WHERE id = ?;";
        private final int PORT = 3306;

        private MysqlDataSource mysqlDS = null;
        private Connection conn = null;
        private PreparedStatement ps = null;

        private void initContext() throws Exception {
            if (DRAGONWELL.equals(PROVIDER)) {
                Security.insertProviderAt(new DragonwellSecurityProvider(), 1);
            } else if (KONA.equals(PROVIDER)) {
                Security.insertProviderAt(new KonaProvider(), 1);
            }

            String trustCA = extractLibrary(SMTlsMySQLBenchmark.class.getClassLoader(), "truststore.jks");
            mysqlDS = new MysqlDataSource();
            mysqlDS.setUseSSL(true);
            mysqlDS.setTrustCertificateKeyStoreType("JKS");
            mysqlDS.setTrustCertificateKeyStoreUrl(trustCA);
            mysqlDS.setTrustCertificateKeyStorePassword(JKS_PASSWORD);

            mysqlDS.setServerName(HOST_NAME);
            mysqlDS.setPort(PORT);
            mysqlDS.setUser(USER);
            mysqlDS.setPassword(SQL_PASSWORD);
            mysqlDS.setDatabaseName(DATA_BASE);

            conn = mysqlDS.getConnection();

            String sql = "SELECT image_data FROM images_table WHERE id = ?;";
            ps = conn.prepareStatement(sql);
            ps.setInt(1, 1);
        }

        public PreparedStatement getPreparedStatement() {
            return ps;
        }

        @Setup
        public void createContext() throws Exception {
            initContext();
        }

        @TearDown
        public void teardown() throws Exception {
            ps.close();
            conn.close();
        }

        private String extractLibrary(ClassLoader classLoader, String name) throws Exception {
            int pos = name.lastIndexOf('.');
            File file = File.createTempFile(name.substring(0, pos), name.substring(pos));
            String fullPath = file.getAbsolutePath();
            try (InputStream in = classLoader.getResourceAsStream(name);
                 OutputStream out = new FileOutputStream(file)) {
                byte[] buf = new byte[4096];
                int length;
                while ((length = in.read(buf)) > 0) {
                    out.write(buf, 0, length);
                }
            } finally {
                file.deleteOnExit();
            }
            return fullPath;
        }
    }
}
