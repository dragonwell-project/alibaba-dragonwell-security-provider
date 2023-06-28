#!/bin/sh

mvn clean package

java -cp ./target/demo-1.0-SNAPSHOT-jar-with-dependencies.jar com.alibaba.dragonwell.security.tls.demo.SMDemo