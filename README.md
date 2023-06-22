Dragonwell Security Provider - A High Performance Java Security Provider
========================================

Dragonwell Security Provider is a Java Security Provider (JSP) that implements parts of the Java
Cryptography Extension (JCE) and Java Secure Socket Extension (JSSE).  It uses
[Tongsuo](https://github.com/Tongsuo-Project/Tongsuo) to provide cryptographic primitives and Transport Layer Security (TLS)
for Java applications on OpenJDK.  See [the capabilities
documentation](CAPABILITIES.md) for detailed information on what is provided.

Dragonwell Security Provider inherits from Google's project [Conscrypt](https://github.com/google/conscrypt). The core SSL engine has borrowed liberally from the [Netty](http://netty.io/) project and their
work on [netty-tcnative](http://netty.io/wiki/forked-tomcat-native.html), giving `Dragonwell Security Provider`
similar performance.

In addition to supporting international mainstream en-decryption Algorithms and SSL/TLS protocols, Dragonwell Security Provider also provides support for China's ShangMi Algorithms [SM2](https://github.com/alipay/tls13-sm-spec/tree/master/sm-en-pdfs/sm2)/[SM3](https://github.com/alipay/tls13-sm-spec/tree/master/sm-en-pdfs/sm3)/[SM4](https://github.com/alipay/tls13-sm-spec/tree/master/sm-en-pdfs/sm4) and [RFC8998](https://datatracker.ietf.org/doc/html/rfc8998) TLS protocol.

<table>
  <tr>
    <td><b>Homepage:</b></td>
    <td>
      <a href="https://github.com/dragonwell-project/alibaba-dragonwell-security-provider">github.com/dragonwell-project/alibaba-dragonwell-security-provider</a>
    </td>
  </tr>
  <tr>
    <td><b>Mailing List:</b></td>
    <td>
      <a>jeffery.wsj@alibaba-inc.com</a>
    </td>
  </tr>
</table>

Download
-------------
Dragonwell Security Provider supports **Java 8/11** OpenJDK.  The build artifacts are available on Maven Central.

### Download JARs
You can download
[the JARs](http://search.maven.org/#search%7Cga%7C1%7Cg:%22org.conscrypt%22)
directly from the Maven repositories.

### OpenJDK

#### Native Classifiers

The OpenJDK artifacts are platform-dependent since each embeds a native library for a particular
platform. We publish artifacts to Maven Central for the following platforms:

Classifier | OS | Architecture
-----------| ------- | ---------------- |
linux-x86_64 | Linux | x86_64 (64-bit)
linux-aarch_64 | Linux | aarch_64 (64-bit)
osx-x86_64 | Mac | x86_64 (64-bit)
osx-aarch_64(M1) | Mac | aarch_64 (64-bit)

#### Maven

Use the [os-maven-plugin](https://github.com/trustin/os-maven-plugin) to add the dependency:

```xml
<build>
  <extensions>
    <extension>
      <groupId>kr.motd.maven</groupId>
      <artifactId>os-maven-plugin</artifactId>
      <version>1.4.1.Final</version>
    </extension>
  </extensions>
</build>

<dependency>
  <groupId>com.alibaba.dragonwell</groupId>
  <artifactId>security-native</artifactId>
  <version>1.0.0</version>
  <classifier>${os.detected.classifier}</classifier>
</dependency>
```

#### Gradle
Use the [osdetector-gradle-plugin](https://github.com/google/osdetector-gradle-plugin)
(which is a wrapper around the os-maven-plugin) to add the dependency:

```gradle
buildscript {
  repositories {
    mavenCentral()
  }
  dependencies {
    classpath 'com.google.gradle:osdetector-gradle-plugin:1.4.0'
  }
}

// Use the osdetector-gradle-plugin
apply plugin: "com.google.osdetector"

dependencies {
  compile 'com.alibaba.dragonwell:security-native:1.0.0:' + osdetector.classifier
}
```

#### Uber JAR

For convenience, we also publish an Uber JAR to Maven Central that contains the shared
libraries for all of the published platforms. While the overall size of the JAR is
larger than depending on a platform-specific artifact, it greatly simplifies the task of
dependency management for most platforms.

To depend on the uber jar, simply use the `security-native-uber` artifacts.

##### Maven
```xml
<dependency>
  <groupId>com.alibaba.dragonwell</groupId>
  <artifactId>security-native-uber</artifactId>
  <version>1.0.0</version>
</dependency>
```

##### Gradle
```gradle
dependencies {
  compile 'com.alibaba.dragonwell:security-native-uber:1.0.0'
}
```

How to Build
------------

If you are making changes to Dragonwell Security Provider, see the [building
instructions](BUILDING.md).
