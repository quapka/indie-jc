# Multiparty Hardware-backed Seed Derivation Service

This is an open-source artifact accompanying the submission of the Multiparty
Hardware-backed Seed Derivation Service. The main part of the protocol is
implemnted in `DiscreteLogEquality.java, DistributedKeyGen.java`, and
`IndistinguishabilityApplet.java`.

This project uses Nix(OS), to setup the enviromnet install Nix, and run `nix develop`.
Then you can insert the required number of JavaCards (tested up to five) and install the applets
with. For example, to install 2-out-of-3 configuration do:

```bash
./reinstall-applet.sh 2 3
```

Now, you can run all the tests with:

```bash
./test-all.sh
```

The most interesting tests, that try the full Distributed Key Generation and seed derivation, can be ran with:

```bash
./test_integration_jcop4.sh -- -Pthreshold=2 -PnParties=3 --rerun-tasks --info --tests AppletTest.testDleqKeyGeneration
./test_integration_jcop4.sh -- -Pthreshold=2 -PnParties=3 --rerun-tasks --info --tests AppletTest.testDeriveDleqFromJWT
```


## Acknowledgements

Musig2 implementation was sources from:
https://github.com/SPXcz/musig2-applet

[![Build Status](https://travis-ci.org/ph4r05/javacard-gradle-template.svg?branch=master)](https://travis-ci.org/ph4r05/javacard-gradle-template)

This is simple JavaCard project template using Gradle build system.

You can develop your JavaCard applets and build cap files with the Gradle!
Moreover the project template enables you to test the applet with [JCardSim] or on the physical cards.

Gradle project contains one module:

- `applet`: contains the javacard applet. Can be used both for testing and building CAP

Features:
 - Gradle build (CLI / IntelliJ Idea)
 - Build CAP for applets
 - Test applet code in [JCardSim] / physical cards
 - IntelliJ Idea: Coverage
 - Travis support 

## How to use

- Clone this template repository:

```bash
git clone --recursive https://github.com/ph4r05/javacard-gradle-template.git
```

- Implement your applet in the `applet` module.

- Run Gradle wrapper `./gradlew` on Unix-like system or `./gradlew.bat` on Windows
to build the project for the first time (Gradle will be downloaded if not installed).

## Building cap

- Setup your Applet ID (`AID`) in the `./applet/build.gradle`.

- Run the `buildJavaCard` task:

```bash
./gradlew buildJavaCard  --info --rerun-tasks
```

Generates a new cap file `./applet/out/cap/applet.cap`

Note: `--rerun-tasks` is to force re-run the task even though the cached input/output seems to be up to date.

Typical output:

```
[ant:cap] [ INFO: ] Converter [v3.0.5]
[ant:cap] [ INFO: ]     Copyright (c) 1998, 2015, Oracle and/or its affiliates. All rights reserved.
[ant:cap]     
[ant:cap]     
[ant:cap] [ INFO: ] conversion completed with 0 errors and 0 warnings.
[ant:verify] XII 10, 2017 10:45:05 ODP.  
[ant:verify] INFO: Verifier [v3.0.5]
[ant:verify] XII 10, 2017 10:45:05 ODP.  
[ant:verify] INFO:     Copyright (c) 1998, 2015, Oracle and/or its affiliates. All rights reserved.
[ant:verify]     
[ant:verify]     
[ant:verify] XII 10, 2017 10:45:05 ODP.  
[ant:verify] INFO: Verifying CAP file /Users/dusanklinec/workspace/jcard/applet/out/cap/applet.cap
[ant:verify] javacard/framework/Applet
[ant:verify] XII 10, 2017 10:45:05 ODP.  
[ant:verify] INFO: Verification completed with 0 warnings and 0 errors.
```

## Installation on a (physical) card

```bash
./gradlew installJavaCard
```

Or inspect already installed applets:

```bash
./gradlew listJavaCard
```
