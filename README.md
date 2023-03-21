Tongsuo-Java-SDK - A Java Security Provider
========================================

Tongsuo-Java-SDK is a Java Security Provider (JSP) that implements parts of the
Java Cryptography Extension (JCE) and Java Secure Socket Extension (JSSE).  It
uses Tongsuo to provide cryptographic primitives and Transport Layer Security
(TLS) for Java applications on Android and OpenJDK.  See [the capabilities
documentation](CAPABILITIES.md) for detailed information on what is provided.

The core SSL engine has borrowed liberally from the [Netty](http://netty.io/)
project and their work on [netty-tcnative](http://netty.io/wiki/forked-tomcat-native.html),
giving `Tongsuo` similar performance.


Download
-------------
Tongsuo-Java-SDK supports **Java 7** or later on OpenJDK and **Gingerbread (API
Level 9)** or later on Android.  The build artifacts are available on Maven
Central.

### Download JARs
You can download
[the JARs](http://search.maven.org/#search%7Cga%7C1%7Cg:%22net.tongsuo%22)
directly from the Maven repositories.

### OpenJDK (i.e. non-Android)

#### Native Classifiers

The OpenJDK artifacts are platform-dependent since each embeds a native library for a particular
platform. We publish artifacts to Maven Central for the following platforms:

Classifier | OS | Architecture
-----------| ------- | ---------------- |
linux-x86_64 | Linux | x86_64 (64-bit)



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
  <groupId>net.tongsuo</groupId>
  <artifactId>tongsuo-openjdk</artifactId>
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
  compile 'net.tongsuo:tongsuo-openjdk:1.0.0:' + osdetector.classifier
}
```

How to Build
------------

If you are making changes to Tongsuo Security Provider, see the [building instructions](BUILDING.md).
