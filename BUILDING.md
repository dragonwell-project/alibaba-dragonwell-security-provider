Building Alibaba Dragonwell Security Provider
==================

Before you begin, you'll first need to properly configure the [Prerequisites](#Prerequisites) as
described below.

Then to build, run:

```bash
$ ./gradlew build -PtongsuoHome=/opt/tongsuo -PjdkHome=/path/to/jdk
```

To publish the artifacts to your Maven local repository for use in your own project, run:

```bash
$ ./gradlew publishToMavenLocal -PtongsuoHome=/opt/tongsuo -PjdkHome=/path/to/jdk
```

Prerequisites
-------------
Alibaba Dragonwell Security Provider requires that you have __Java__, __Tongsuo__ configured as described
below.

#### Java
The build requires that you have the `JAVA_HOME` environment variable pointing to a valid JDK.


#### Tongsuo
Download Tongsuo and then build as follows:

```bash
wget https://github.com/Tongsuo-Project/Tongsuo/releases/download/8.3.2/BabaSSL-8.3.2.tar.gz
tar xzvf BabaSSL-8.3.2.tar.gz
cd Tongsuo-8.3.2
./config no-shared enable-ntls enable-weak-ssl-ciphers --release --prefix=/opt/tongsuo
make -j
make install
```

Running tests
-------------------------

```bash
./gradlew test -PtongsuoHome=/opt/tongsuo -PjdkHome=/path/to/jdk
```

Coverage
--------
To see coverage numbers, run the tests and then execute the jacocoTestReport rule

```bash
./gradlew check jacocoTestReport -PtongsuoHome=/opt/tongsuo -PjdkHome=/path/to/jdk
```

The report will be placed in `openjdk/build/reports/jacoco/test/html/index.html`
