package org.conscrypt;

import static org.conscrypt.TestUtils.installConscryptAsDefaultProvider;

import org.conscrypt.net.ssl.BabaSSLServerJdkClientTest;
import org.conscrypt.net.ssl.JdkDragonServerBaBaSSLClientTest;
import org.conscrypt.net.ssl.JdkDragonServerJdkClientTest;
import org.conscrypt.net.ssl.JdkDragonServerJdkDragonClientTest;
import org.conscrypt.net.ssl.JdkServerBabaSSLClientTest;
import org.conscrypt.net.ssl.JdkServerJdkClientTest;
import org.conscrypt.net.ssl.JdkServerJdkDragonClientTest;
import org.conscrypt.net.ssl.BaBaSSLServerJdkDragonClientTest;
import org.junit.BeforeClass;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;

@RunWith(Suite.class)
@Suite.SuiteClasses({
    AddressUtilsTest.class,
    ApplicationProtocolSelectorAdapterTest.class,
    ClientSessionContextTest.class,
    ConscryptSocketTest.class,
    ConscryptTest.class,
    DuckTypedPSKKeyManagerTest.class,
    FileClientSessionCacheTest.class,
    NativeCryptoTest.class,
    NativeRefTest.class,
    NativeSslSessionTest.class,
    OpenSSLKeyTest.class,
    OpenSSLX509CertificateTest.class,
    PlatformTest.class,
    ServerSessionContextTest.class,
    SSLUtilsTest.class,
    TestSessionBuilderTest.class,
    TestTLSWithJetty.class,
    // BabaSSLServerJdkClientTest.class,
    // JdkServerBabaSSLClientTest.class,
    // JdkServerJdkClientTest.class,
    BaBaSSLServerJdkDragonClientTest.class,
    JdkDragonServerBaBaSSLClientTest.class,
    JdkDragonServerJdkDragonClientTest.class,
    JdkDragonServerJdkClientTest.class,
    JdkServerJdkDragonClientTest.class,
})
public class ConscryptOpenJdkSuite {

  @BeforeClass
  public static void setupStatic() {
    installConscryptAsDefaultProvider();
  }

}
