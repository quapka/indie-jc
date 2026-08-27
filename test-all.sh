#!/usr/bin/env bash

sleepFor=0
aggResult=0

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

tests=(
    testEncryptedJwtVerificationAndCommitment
    testDebugGood
    testDebugBad
    testIsInitialized
    testDecodeBase64UrlSafe
    testDerivingSalt
    testGettingExampleDleqProof
    testDVRFKeyGeneration
    testDLEQAgainstGeneratedKey
    testSetup
    testAesCtrDecryption
    testVerifyCommitment
    testSetOIDCPublicKey
    testJWTVerification
    testEncryptedJwtVerification
    testBenchmarkDecoding
    testGetCurrentEmptyEpoch
    testGenerateMusig2Key
    testGenerateMusig2Nonce
    testComputePublicTest
    testACoefSerialization
    testMusig2SignatureInternal
    testEpochGeneration
    testNofNEpochGeneration
    testNofNDLEQSetup
    testNofNDleqGetCPoints
    testNofNDleqSetCPoints
    testDleqKeyGeneration
    testDeriveDleq
    testDeriveDleqFromJWT
    testLagrange
)

for testName in "${tests[@]}"; do
    ./test_integration_jcop4.sh -- --tests AppletTest."$testName" || aggResult=$(( $? | $aggResult ))
done

if test $aggResult -ne 0; then
    printf "\n${RED}FAILED${NC}: some tests failed"
else
    printf "\n${GREEN}PASSED${NC}: all tests passed"
fi
