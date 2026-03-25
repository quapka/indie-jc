#!/usr/bin/env bash

sleepFor=0.5

./test_integration_jcop4.sh -- --tests AppletTest.testDebugGood
sleep "$sleepFor"
./test_integration_jcop4.sh -- --tests AppletTest.testDebugBad
sleep "$sleepFor"
./test_integration_jcop4.sh -- --tests AppletTest.testIsInitialized
sleep "$sleepFor"
./test_integration_jcop4.sh -- --tests AppletTest.testDecodeBase64UrlSafe
sleep "$sleepFor"
./test_integration_jcop4.sh -- --tests AppletTest.testDerivingSalt
sleep "$sleepFor"
./test_integration_jcop4.sh -- --tests AppletTest.testGettingExampleDleqProof
sleep "$sleepFor"
./test_integration_jcop4.sh -- --tests AppletTest.testDVRFKeyGeneration
sleep "$sleepFor"
./test_integration_jcop4.sh -- --tests AppletTest.testDLEQAgainstGeneratedKey
sleep "$sleepFor"
./test_integration_jcop4.sh -- --tests AppletTest.testSetup
sleep "$sleepFor"
./test_integration_jcop4.sh -- --tests AppletTest.testAesCtrDecryption
sleep "$sleepFor"
./test_integration_jcop4.sh -- --tests AppletTest.testVerifyCommitment
sleep "$sleepFor"
./test_integration_jcop4.sh -- --tests AppletTest.testSetOIDCPublicKey
sleep "$sleepFor"
./test_integration_jcop4.sh -- --tests AppletTest.testJWTVerification
sleep "$sleepFor"
./test_integration_jcop4.sh -- --tests AppletTest.testEncryptedJwtVerification
sleep "$sleepFor"
./test_integration_jcop4.sh -- --tests AppletTest.testBenchmarkDecoding
sleep "$sleepFor"
./test_integration_jcop4.sh -- --tests AppletTest.testEncryptedJwtVerificationAndCommitment
sleep "$sleepFor"
./test_integration_jcop4.sh -- --tests AppletTest.testGetCurrentEmptyEpoch
sleep "$sleepFor"
./test_integration_jcop4.sh -- --tests AppletTest.testGenerateMusig2Key
sleep "$sleepFor"
./test_integration_jcop4.sh -- --tests AppletTest.testGenerateMusig2Nonce
sleep "$sleepFor"
./test_integration_jcop4.sh -- --tests AppletTest.testComputePublicTest
sleep "$sleepFor"
./test_integration_jcop4.sh -- --tests AppletTest.testACoefSerialization
sleep "$sleepFor"
./test_integration_jcop4.sh -- --tests AppletTest.testMusig2SignatureInternal
sleep "$sleepFor"
./test_integration_jcop4.sh -- --tests AppletTest.testEpochGeneration
sleep "$sleepFor"
./test_integration_jcop4.sh -- --tests AppletTest.testNofNEpochGeneration
sleep "$sleepFor"
./test_integration_jcop4.sh -- --tests AppletTest.testNofNDLEQSecretDerivation
sleep "$sleepFor"
./test_integration_jcop4.sh -- --tests AppletTest.testNofNDLEQSetup
sleep "$sleepFor"
./test_integration_jcop4.sh -- --tests AppletTest.testNofNDleqGetCPoints
sleep "$sleepFor"
./test_integration_jcop4.sh -- --tests AppletTest.testNofNDleqSetCPoints
sleep "$sleepFor"
./test_integration_jcop4.sh -- --tests AppletTest.testDleqKeyGeneration
sleep "$sleepFor"
./test_integration_jcop4.sh -- --tests AppletTest.testDeriveDleq
sleep "$sleepFor"
./test_integration_jcop4.sh -- --tests AppletTest.testLagrange
