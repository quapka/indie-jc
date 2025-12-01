package applet;

import javacard.framework.*;
import javacard.security.RandomData;
import applet.jcmathlib.*;

public class Musig2 {

    // Helper
    private HashCustom digest;
    private RandomData rng;

    // Data storage
    private byte[] digestHelper;
    private byte[] tmpArray;
    private BigNat tmpBigNat;

    // States
    private byte stateKeyPairGenerated; // Set to TRUE if key share pair is generated
    private byte stateReadyForSigning; // Controls whether nonce has been already used
    private byte stateKeysEstablished; // Set to TRUE if group public key is set
    private byte stateNoncesAggregated; // Set to TRUE if nonce is aggregated
    private byte statePreloaded; // For debug purposes. States whether data has been preloaded

    // Crypto arguments
    // Argument names refer to the names of arguments in the founding MuSig 2 paper (p. 15) or BIP-0327
    // https://github.com/bitcoin/bips/blob/master/bip-0327.mediawiki
    // https://eprint.iacr.org/2020/1261.pdf
    private ECCurve curve;
    private ECPoint publicShare;
    private ECPoint groupPubKey;
    private ECPoint coefR; // Temporary attribute (clear after sig complete)
    private ECPoint[] pubNonce;
    private ECPoint[] aggNonce;
    private BigNat secretShare;
    private BigNat coefA;
    private BigNat coefB; // Temporary attribute
    private BigNat challangeE;
    private BigNat partialSig;
    private BigNat modulo;
    private BigNat[] secNonce;

    public Musig2(ECCurve curve, ResourceManager rm) {

        // Helper objects
        digestHelper = JCSystem.makeTransientByteArray(Constants.HASH_LEN, JCSystem.CLEAR_ON_DESELECT);
        digest = new HashCustom();
        rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

        // Helper attributes
        tmpArray = JCSystem.makeTransientByteArray((short) (Constants.POINT_LEN+1), JCSystem.CLEAR_ON_DESELECT);
        stateReadyForSigning = Constants.STATE_FALSE;
        stateNoncesAggregated = Constants.STATE_FALSE;
        stateKeyPairGenerated = Constants.STATE_FALSE;
        stateKeysEstablished = Constants.STATE_FALSE;
        statePreloaded = Constants.STATE_FALSE;

        // Main Attributes
        this.curve = curve;
        modulo = this.curve.rBN;
        groupPubKey = new ECPoint(curve);
        publicShare = new ECPoint(curve);

        coefR = new ECPoint(curve);
        secretShare = new BigNat(Constants.SHARE_LEN, JCSystem.MEMORY_TYPE_PERSISTENT, rm); // Effective private key

        coefA = new BigNat(Constants.HASH_LEN, JCSystem.MEMORY_TYPE_PERSISTENT, rm);
        coefB = new BigNat(Constants.HASH_LEN, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, rm);
        challangeE = new BigNat(modulo.length(), JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, rm);

        partialSig = new BigNat(modulo.length(), JCSystem.MEMORY_TYPE_PERSISTENT, rm);
        tmpBigNat = new BigNat(modulo.length(), JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT, rm);

        pubNonce = new ECPoint[Constants.V];
        secNonce = new BigNat[Constants.V];
        aggNonce = new ECPoint[Constants.V];

        for (short i = (short) 0; i < Constants.V; i++) {
            pubNonce[i] = new ECPoint(curve);
            aggNonce[i] = new ECPoint(curve);
            secNonce[i] = new BigNat(modulo.length(), JCSystem.MEMORY_TYPE_PERSISTENT, rm);

        }
    }

    // Key generation
    public void individualPubkey(byte[] buffer, short offset) {

        if (curve == null
                || publicShare == null
                || secretShare == null
                || tmpArray == null) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            return;
        }

        // Generate private key share
        if (Constants.DEBUG == Constants.STATE_TRUE && buffer[offset] == Constants.STATE_TRUE) {
            if (Constants.DEBUG != Constants.STATE_FALSE) {
                setTestingValues(buffer, offset);
            } else {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
        } else {
            getRandomBigNat(secretShare);
        }

        // Generate public key share
        publicShare.decode(curve.G, (short) 0, (short) curve.G.length);
        publicShare.multiplication(secretShare);

        stateKeyPairGenerated = Constants.STATE_TRUE;
    }

    // Only max. 32B (or the length of a secret key share)
    private void getRandomBigNat (BigNat outBigNat) {
        rng.generateData(tmpArray, (short) 0, Constants.SHARE_LEN);
        outBigNat.fromByteArray(tmpArray, (short) 0, Constants.SHARE_LEN);
    }

    // Single signature only
    // Nonce cant be reused
    public void nonceGen () {

        if (stateKeyPairGenerated != Constants.STATE_TRUE) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        // BIP0327 supports only V=2
        if (Constants.V != 2) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        for (short i = 0; i < Constants.V; i++) {
            generateSecNonce(secNonce[i], i);
            pubNonce[i].setW(curve.G, (short) 0, (short) curve.G.length);
            pubNonce[i].multiplication(secNonce[i]);
        }

        stateReadyForSigning = Constants.STATE_TRUE;

    }

    private void generateSecNonce (BigNat secNonceLocal, short kIndex) {

        BigNat rand = tmpBigNat;

        // Digest randomly generated data
        if (Constants.DEBUG == Constants.STATE_TRUE && statePreloaded == Constants.STATE_TRUE) {
            if (Constants.DEBUG != Constants.STATE_FALSE) {
                // rand.fromByteArray(Constants.RAND_TEST, (short) 0, Constants.SHARE_LEN);
                return;
            } else {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
        } else {
            getRandomBigNat(rand);
        }

        rand.copyToByteArray(digestHelper, (short) 0);
        digest.init(HashCustom.MUSIG_NONCE);
        digest.update(digestHelper, (short) 0, Constants.SHARE_LEN);

        // Digest public key share of the card
        tmpArray[0] = Constants.XCORD_LEN;
        publicShare.encode(tmpArray, (short) 1, true);
        digest.update(tmpArray, (short) 0, (short) (Constants.XCORD_LEN + 1));

        // Digest group public key if it is already established
        if (stateKeysEstablished == Constants.STATE_TRUE) {
            tmpArray[0] = (short)(Constants.XCORD_LEN-1);
            groupPubKey.getX(tmpArray, (short) 1);
            digest.update(tmpArray, (short) 0, Constants.XCORD_LEN); // +1 for the length attribute and -1 for Xonly encoding
        } else {
            tmpArray[0] = (byte) 0x00;
            digest.update(tmpArray, (short) 0, (short) 1);
        }

        // Add rest of the arguments (most are currently not defined)
        tmpArray[0] = (byte) 0x00; // m_prefixed
        tmpArray[1] = (byte) 0x00; // 1-4 are length of extra_in
        tmpArray[2] = (byte) 0x00;
        tmpArray[3] = (byte) 0x00;
        tmpArray[4] = (byte) 0x00;
        tmpArray[5] = (byte) kIndex; // Index of the secret nonce. Either 0 or 1

        digest.doFinal(tmpArray,
                (short) 0x00,
                (short) 6,
                digestHelper,
                (short) 0);

        secNonceLocal.fromByteArray(digestHelper, (short) 0, Constants.HASH_LEN);
        secNonceLocal.mod(modulo);

        if (secNonceLocal.isZero()) {
            ISOException.throwIt(Constants.E_POSSIBLE_SECNONCE_REUSE);
        }
    }

    public short sign(byte[] messageBuffer,
                      short inOffset,
                      short msgLength,
                      byte[] outBuffer,
                      short outOffset) {
 
        System.out.println("sign 0");
        if (stateReadyForSigning != Constants.STATE_TRUE) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        System.out.println("sign 1");

        if (stateNoncesAggregated != Constants.STATE_TRUE) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        System.out.println("sign 2");

        if (msgLength > Constants.MAX_MESSAGE_LEN) {
            ISOException.throwIt(Constants.E_MESSAGE_TOO_LONG);
            return (short) -1;
        }
        System.out.println("sign 3");

        if ((short) (inOffset + msgLength) > Constants.MAX_JC_BUFFER_LEN) {
            ISOException.throwIt(Constants.E_BUFFER_OVERLOW);
            return (short) -1;
        }
        System.out.println("sign 4");

        if ((short) (outOffset + Constants.XCORD_LEN + Constants.SHARE_LEN) > Constants.MAX_JC_BUFFER_LEN) {
            ISOException.throwIt(Constants.E_BUFFER_OVERLOW);
            return (short) -1;
        }
        System.out.println("sign 5");

        for (short i = 0; i < Constants.V; i++) {
            if (secNonce[i].isZero()) {
                ISOException.throwIt(Constants.E_POSSIBLE_SECNONCE_REUSE);
            }
        }
        System.out.println("sign 6");

        generateCoefB(messageBuffer, inOffset, msgLength);
        // System.out.println("sign 7");
        generateCoefR();
        // System.out.println("sign 8");
        generateChallengeE(messageBuffer, inOffset, msgLength);
        // System.out.println("sign 9");
        signPartially();
        // System.out.println("sign 10");

        writePartialSignatureOut(outBuffer, outOffset);
        System.out.println("sign 11");

        eraseNonce();
        System.out.println("sign 12");

        stateReadyForSigning = Constants.STATE_FALSE;
        stateNoncesAggregated = Constants.STATE_FALSE;
        System.out.println("sign 13");

        return modulo.length();
    }

    private void generateCoefB (byte[] messageBuffer, short offset, short length) {

        if (stateNoncesAggregated != Constants.STATE_TRUE || stateKeysEstablished != Constants.STATE_TRUE) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            return;
        }

        digest.init(HashCustom.MUSIG_NONCECOEF);

        // Hash public aggregated nonces
        for (short i = 0; i < Constants.V; i++) {
            digestPoint(aggNonce[i], true);
        }

        // Hash public key
        // Must be encoded using xbytes
        digestPoint(groupPubKey, false);

        // groupPubKey.encode(tmpArray, (short) 0, true);
        // System.out.println("Card: groupPubKey.compressed");
        // for ( int i = 0; i < (short) 33; i++ ) {
        //     System.out.print(String.format("%02X", tmpArray[i]));
        // }
        // System.out.println();

        // groupPubKey.getX(tmpArray, (short) 0);
        // System.out.println("Card: groupPubKey.X");
        // for ( int i = 0; i < (short) 32; i++ ) {
        //     System.out.print(String.format("%02X", tmpArray[i]));
        // }
        // System.out.println();

        // System.out.println("Card: message");
        // for ( int i = offset; i < (short) offset + length; i++ ) {
        //     System.out.print(String.format("%02X", messageBuffer[i]));
        // }
        // System.out.println();
        // Hash the message to be signed
        digest.doFinal(messageBuffer, offset, length, tmpArray, (short) 0);
        // System.out.println("Card: doFinal digest");
        // for ( int i = offset; i < (short) offset + length; i++ ) {
        //     System.out.print(String.format("%02X", tmpArray[i]));
        // }
        // System.out.println();
        coefB.fromByteArray(tmpArray, (short) 0, Constants.HASH_LEN);
        coefB.mod(modulo);


//         byte[] expCoefB = new byte[] { (byte) 0x24, (byte) 0x5F, (byte) 0x37, (byte) 0x41, (byte) 0xE5, (byte) 0xAB, (byte) 0x1D, (byte) 0x19, (byte) 0x2C, (byte) 0x06, (byte) 0x94, (byte) 0xC5, (byte) 0x7B, (byte) 0x3F, (byte) 0xEA, (byte) 0x8D, (byte) 0x54, (byte) 0x68, (byte) 0xF0, (byte) 0xFA, (byte) 0x2D, (byte) 0xE8, (byte) 0xD7, (byte) 0xB0, (byte) 0x18, (byte) 0x24, (byte) 0xDB, (byte) 0x80, (byte) 0xFA, (byte) 0xC5, (byte) 0x8A, (byte) 0xBC };

//         coefB.copyToByteArray(tmpArray, (short) 0);
//         System.out.println("Card: generateCoefB");
//         for ( int i = 0; i < (short) 32; i++ ) {
//             System.out.print(String.format("%02X", tmpArray[i]));
//         }
//         System.out.println();
    }

    private void generateCoefR () {

        if (stateNoncesAggregated != Constants.STATE_TRUE) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            return;
        }

        // Initalize R using R1
        coefR.copy(aggNonce[1]);

        coefR.multAndAdd(coefB, aggNonce[0]);

//         coefR.encode(tmpArray, (short) 0, true);
//         System.out.println("Card: generateCoefR");
//         for ( int i = 0; i < (short) 33; i++ ) {
//             System.out.print(String.format("%02X", tmpArray[i]));
//         }
//         System.out.println();
    }

    private void generateChallengeE (byte[] messageBuffer, short offset, short length) {

        if (stateNoncesAggregated != Constants.STATE_TRUE || stateKeysEstablished != Constants.STATE_TRUE) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            return;
        }

        digest.init(HashCustom.BIP_CHALLENGE);

        digestPoint(coefR, false);
        digestPoint(groupPubKey, false);

        digest.doFinal(messageBuffer, offset, length, tmpArray, (short) 0);
        challangeE.fromByteArray(tmpArray, (short) 0, Constants.HASH_LEN);
        challangeE.mod(modulo);

//         challangeE.copyToByteArray(tmpArray, (short) 0);
//         System.out.println("Card: generateChallengeE");
//         for ( int i = 0; i < (short) 32; i++ ) {
//             System.out.print(String.format("%02X", tmpArray[i]));
//         }
//         System.out.println();
    }

    // Creates the partial signature itself
    private void signPartially () {

        if (!coefR.isYEven()) {
            for (short i = 0; i < Constants.V; i++) {
                tmpBigNat.copy(modulo);
                tmpBigNat.subtract(secNonce[i]);
                secNonce[i].copy(tmpBigNat);
            }
        }

        // don't copy to optimize? is challengeE expected to be used anyway?
        partialSig.copy(challangeE);

        // CoefA is a public coeficient and is often equal to 1
        if (!coefA.isOne()) {
            coefA.copyToByteArray(tmpArray, (short) 0);
            partialSig.modMult(coefA, modulo);
        }

        // Implements the coefG coeficient which is either equal to 1 or -1
        if (!groupPubKey.isYEven()) {
            partialSig.modNegate(modulo);
        }

        partialSig.modMult(secretShare, modulo);
        partialSig.modAdd(secNonce[0], modulo);

        tmpBigNat.copy(coefB);
        tmpBigNat.modMult(secNonce[1], modulo);

        partialSig.modAdd(tmpBigNat, modulo);

        // partialSig.copyToByteArray(tmpArray, (short) 0);
        // System.out.println("Card: signPartially");
        // for ( int i = 0; i < (short) 32; i++ ) {
        //     System.out.print(String.format("%02X", tmpArray[i]));
        // }
        // System.out.println();
    }

    // Format: psig
    private void writePartialSignatureOut (byte[] outbuffer, short offset) {

        if ((short) (offset + Constants.SHARE_LEN) > Constants.MAX_JC_BUFFER_LEN) {
            ISOException.throwIt(Constants.E_BUFFER_OVERLOW);
        }

        partialSig.copyToByteArray(outbuffer, offset);
    }

    private void digestPoint (ECPoint point, boolean cbytes) {

        short length;

        if (cbytes) {
            point.encode(tmpArray, (short) 0, true);
            length = (short) 33;
        } else {
            point.getX(tmpArray, (short) 0);
            length = (short) 32;
        }

        digest.update(tmpArray, (short) 0, length);
    }

    // Nonce must be erased after signing, otherwise the private key is revealed if used twice.
    private void eraseNonce () {

        for (short i = 0; i < Constants.V; i++) {
            pubNonce[i].randomize();
            aggNonce[i].randomize();
            secNonce[i].erase();
        }

        challangeE.erase();
        coefB.erase();
        coefR.randomize();

    }

    // Bitcoin public key format
    public void getXonlyPubKey(byte[] buffer, short offset) {

        if (stateKeyPairGenerated != Constants.STATE_TRUE) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        if ((short)(offset + Constants.XCORD_LEN) > Constants.MAX_JC_BUFFER_LEN) {
            ISOException.throwIt(Constants.E_BUFFER_OVERLOW);
        }

        short len = publicShare.getX(buffer, offset);

        if (len != (Constants.XCORD_LEN - 1)) {
            ISOException.throwIt(Constants.E_WRONG_XCORD_LEN);
        }
    }

    public void getPlainPubKey (byte[] buffer, short offset) {

        if (stateKeyPairGenerated != Constants.STATE_TRUE) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        if ((short)(offset + Constants.XCORD_LEN) > Constants.MAX_JC_BUFFER_LEN) {
            ISOException.throwIt(Constants.E_BUFFER_OVERLOW);
        }

        short len = publicShare.encode(buffer, offset, true);

        if (len != Constants.XCORD_LEN) {
            ISOException.throwIt(Constants.E_WRONG_XCORD_LEN);
        }
    }

    //In format v1, v2, v3, v4, ...
    public void getPublicNonceShare (byte[] buffer, short offset) {

        // Is nonce generated?
        if (stateReadyForSigning != Constants.STATE_TRUE) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        if ((short)(offset + Constants.XCORD_LEN * Constants.V) > Constants.MAX_JC_BUFFER_LEN) {
            ISOException.throwIt(Constants.E_BUFFER_OVERLOW);
        }

        short currentOffset = offset;

        for (short i = (short) 0; i < Constants.V; i++) {
            //Here's the place of the suspected bug
            pubNonce[i].encode(buffer, currentOffset, true);
            currentOffset += Constants.XCORD_LEN;
        }
    }

    // Public key, coefA (33+32)
    public void setGroupPubKey (byte[] firstRoundData, short offset) {

        // System.out.println("setGroupKey 0");
        if ((short)(offset + Constants.XCORD_LEN + Constants.SHARE_LEN) > Constants.MAX_JC_BUFFER_LEN) {
            ISOException.throwIt(Constants.E_BUFFER_OVERLOW);
        }
        // System.out.println("setGroupKey 1");

        this.groupPubKey.decode(firstRoundData, offset, Constants.XCORD_LEN);
        // System.out.println("setGroupKey 2");
        coefA.fromByteArray(firstRoundData, (short) (offset + Constants.XCORD_LEN), Constants.SHARE_LEN);
        // System.out.println("setGroupKey 3");

        // System.out.println("setGroupKey 4");
        stateKeysEstablished = Constants.STATE_TRUE;
    }

    // 33 + 33
    public void setNonceAggregate (byte[] nonces, short offset) {

        short currentOffset = offset;

        // System.out.println("1");
        if ((short)(offset + 2 * Constants.XCORD_LEN) > Constants.MAX_JC_BUFFER_LEN) {
            ISOException.throwIt(Constants.E_BUFFER_OVERLOW);
        }

        // System.out.println("2");
        // System.out.println(String.format("%02X", nonces[offset]));
        // System.out.println(offset);
        // for(short i = offset; i < (short) (offset + 33); i++ ) {
        //     System.out.print(String.format("%02X", nonces[i]));
        // }
        // System.out.println();
        // for(short i = (short) (offset + 33) ; i < (short) (offset + 66); i++ ) {
        //     System.out.print(String.format("%02X", nonces[i]));
        // }
        // System.out.println();
        if (nonces[offset] != (byte) 0x02 && nonces[offset] != (byte) 0x03) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        // System.out.println("3");
        aggNonce[0].decode(nonces, offset, Constants.XCORD_LEN);
        currentOffset += Constants.XCORD_LEN;

        // System.out.println("4");
        if (nonces[currentOffset] != (byte) 0x02 && nonces[currentOffset] != (byte) 0x03) {
            ISOException.throwIt(ISO7816.SW_DATA_INVALID);
        }

        // System.out.println("5");
        aggNonce[1].decode(nonces, currentOffset, Constants.XCORD_LEN);

        // System.out.println("6");
        stateNoncesAggregated = Constants.STATE_TRUE;
    }

    // sk + pk + aggpk + pubnonce + secnonce  (5 + 32 + 33 + 33 + 66 + 64)
    public short setTestingValues (byte[] buffer, short offset) {

            // System.out.println("setTestingValues 0");
            if (Constants.DEBUG == Constants.STATE_FALSE) {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
            // System.out.println("setTestingValues 1");

            short currentOffset = (short) (offset + 5);

            if (Constants.DEBUG != Constants.STATE_TRUE) {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
            // System.out.println("setTestingValues 2");

            // Secret key
            if (buffer[offset] == Constants.STATE_TRUE) {
                // System.out.println("setTestingValues secret key");
                secretShare.fromByteArray(buffer, currentOffset, Constants.SHARE_LEN);
                currentOffset += Constants.SHARE_LEN;
                statePreloaded = Constants.STATE_TRUE;
            }
            // System.out.println("setTestingValues 3");

            // Public key
            if (buffer[(short)(offset + 1)] == Constants.STATE_TRUE) {
                // System.out.println("setTestingValues public key");
                publicShare.decode(buffer, currentOffset, Constants.XCORD_LEN);
                currentOffset += Constants.XCORD_LEN;
                stateKeyPairGenerated = Constants.STATE_TRUE;
                statePreloaded = Constants.STATE_TRUE;
            }
            // System.out.println("setTestingValues 4");

            // Group public key
            if (buffer[(short)(offset + 2)] == Constants.STATE_TRUE) {
                // System.out.println("setTestingValues group public key");
                groupPubKey.decode(buffer, currentOffset, Constants.XCORD_LEN);
                stateKeysEstablished = Constants.STATE_TRUE;
                currentOffset += Constants.XCORD_LEN;
                statePreloaded = Constants.STATE_TRUE;
            }

            // Aggregated nonce
            if (buffer[(short)(offset + 3)] == Constants.STATE_TRUE) {

                if (buffer[currentOffset] != (byte) 0x02 && buffer[currentOffset] != (byte) 0x03) {
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                }

                aggNonce[0].decode(buffer, currentOffset, Constants.XCORD_LEN);
                currentOffset += Constants.XCORD_LEN;

                if (buffer[currentOffset] != (byte) 0x02 && buffer[currentOffset] != (byte) 0x03) {
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                }

                // System.out.println("setTestingValues agg nonce");
                aggNonce[1].decode(buffer, currentOffset, Constants.XCORD_LEN);
                currentOffset += Constants.XCORD_LEN;
                stateNoncesAggregated = Constants.STATE_TRUE;
                stateReadyForSigning = Constants.STATE_TRUE;
                statePreloaded = Constants.STATE_TRUE;
            }
            // System.out.println("setTestingValues 6");

            // Secnonce
            if (buffer[(short)(offset + 4)] == Constants.STATE_TRUE) {
                // System.out.println("setTestingValues secret nonce");
                secNonce[0].fromByteArray(buffer, currentOffset, Constants.SHARE_LEN);
                currentOffset += Constants.SHARE_LEN;
                secNonce[1].fromByteArray(buffer, currentOffset, Constants.SHARE_LEN);
                currentOffset += Constants.SHARE_LEN;
                currentOffset += Constants.XCORD_LEN; // Also includes PK for some reason
                statePreloaded = Constants.STATE_TRUE;
            }

            return currentOffset;
    }

    public void reset () {
        stateKeyPairGenerated = Constants.STATE_FALSE;
        stateReadyForSigning = Constants.STATE_FALSE;
        stateKeysEstablished = Constants.STATE_FALSE;
        stateNoncesAggregated = Constants.STATE_FALSE;
        statePreloaded = Constants.STATE_FALSE;
    }

    public void dereference() {
        digest = null;
        rng = null;
        digestHelper = null;
        tmpArray = null;
        tmpBigNat = null;
        curve = null;
        publicShare = null;
        groupPubKey = null;
        coefR = null;

        for (short i = 0; i < Constants.V; i++) {
            aggNonce[i] = null;
            secNonce[i] = null;
            pubNonce[i] = null;
        }

        pubNonce = null;
        aggNonce = null;
        secretShare = null;
        coefA = null;
        coefB = null;
        challangeE = null;
        partialSig = null;
        modulo = null;
        secNonce = null;
    }
}
