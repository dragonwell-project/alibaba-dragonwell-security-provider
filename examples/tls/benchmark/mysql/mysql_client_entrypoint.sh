#!/bin/bash

apt update -y && apt install openjdk-11-jdk maven -y

# build mysql client benchmark.
mvn clean package

WORK_DIR=`pwd`

# replace mysql's properity file
mkdir -p target/tmp && cp target/benchmark-1.0.0-jar-with-dependencies.jar target/tmp
pushd target/tmp
jar -xvf benchmark-1.0.0-jar-with-dependencies.jar && rm -rf benchmark-1.0.0-jar-with-dependencies.jar
cp ${WORK_DIR}/src/main/resources/TlsSettings.properties ./com/mysql/cj/
jar -cvf benchmark-1.0.0-jar-with-dependencies.jar ./
popd

# run with provider Dragonwell
java -cp target/tmp/benchmark-1.0.0-jar-with-dependencies.jar -DProvider=Dragonwell com.alibaba.dragonwell.security.mysql.SMTlsMySQLBenchmark
# run with provider Kona
java -cp target/tmp/benchmark-1.0.0-jar-with-dependencies.jar -DProvider=Kona com.alibaba.dragonwell.security.mysql.SMTlsMySQLBenchmark