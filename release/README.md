# How to Create a Dragonwell Security Provider Release

## Platforms

Dragonwell Security Provider is built on github CI/CD Action runners, which contains four platform:

Classifier | OS | Architecture
-----------| ------- | ---------------- |
linux-x86_64 | Linux | x86_64 (64-bit)
linux-aarch_64 | Linux | aarch_64 (64-bit)
osx-x86_64 | Mac | x86_64 (64-bit)
osx-aarch_64(M1) | Mac | aarch_64 (64-bit)

## Setup OSSRH and GPG
If you haven't deployed artifacts to Maven Central before, you need to setup your OSSRH (OSS Repository Hosting) account and signing keys.

Follow the instructions on this page to set up an account with OSSRH.
You only need to create the account, not set up a new project
Contact a Conscrypt maintainer to add your account after you have created it.
Install GnuPG and generate your key pair.
Publish your public key to make it visible to the Sonatype servers (e.g. gpg --keyserver pgp.mit.edu --send-key <key ID>).
Get the signing certificates
Contact an existing Conscrypt maintainer to get the keystore containing the code signing certificate.

Set up gradle.properties
Add your OSSRH credentials, GPG key information, and the code signing keystore details to $HOME/.gradle/gradle.properties.

signing.keyId=<8-character-public-key-id>
signing.password=<key-password>
signing.secretKeyRingFile=<your-home-directory>/.gnupg/secring.gpg

signingKeystore=<path-to-keystore>
signingPassword=<keystore-password>
signKeyAlias=<key-alias>

ossrhUsername=<ossrh-username>
ossrhPassword=<ossrh-password>
checkstyle.ignoreFailures=false

## Collect jar files from local maven repository

Dragonwell Security Provider's github CI/CD Action runner will store
multi-platform's local released artifacts. Task one action as an example(https://github.com/dragonwell-project/alibaba-dragonwell-security-provider/actions/runs/5379012066).

## Release security-native-uber artifact

Download the m2repo-uber from github CI/CD Action which is corresponding to the patch you plan to release. Then copy them to the your local maven .m2 repository.

1. Publish security-native-uber jar to OSSRH

`./gradlew security-native-uber:publish -Dorg.gradle.parallel=false -Dcom.alibaba.dragonwell.security.native.buildUberJar=true`

2. Visit the OSSRH site and close and release the repository.

## Release multi-platform security-native artifact

1. Publish multi-platform security-native to OSSRH

`./gradlew security-native:publish -Dorg.gradle.parallel=false -Dcom.alibaba.dragonwell.security.native.releaseJar=true`

2. Visit the OSSRH site and close and release the repository.

3. Note that the publish is dependent on security-native-uber's publish.
