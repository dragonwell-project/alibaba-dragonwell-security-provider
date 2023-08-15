#!/bin/bash

echo "SM4 and AES Encrypt Benchmark:"

mvn clean package && java -cp target/benchmark-1.0-SNAPSHOT-jar-with-dependencies.jar com.alibaba.dragonwell.security.jce.benchmark.SMCryptoBenchmark