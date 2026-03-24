package applet;

// Source: https://github.com/OpenCryptoProject/JCMathLib
import applet.jcmathlib.BigNat;
import applet.jcmathlib.SecP256r1;
import applet.jcmathlib.ECPoint;
import applet.jcmathlib.ECCurve;

import javacard.framework.Util;
import javacard.framework.JCSystem;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.security.ECPublicKey;
import javacard.security.ECPrivateKey;
import javacard.security.RandomData;
import javacard.security.MessageDigest;
import javacard.framework.APDU;

public class DiscreteLogEquality {
    // FIXME M is H actually :D
    public static ECPoint G, com1, com2, userPoint, M, tmpPoint, publicShare, hashToCurvePoint, partialDerivedShare;
    public static BigNat r, ch, tmpNum, secretShare;
    public static BigNat curveOrder;
    public static BigNat aBN, bBN;
    private byte[] tmp = new byte[128];
    private byte[] tmp2 = new byte[32];
    public boolean initialized = false;
    MessageDigest hasher = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
    public static final byte[] HASH_DLEQ_DOMAIN_SEPARATOR = {
        'D', 'i', 's', 'c', 'r', 'e', 't', 'e', ' ',
        'l', 'o', 'g', ' ',
        'e', 'q', 'u', 'a', 'l', 'i', 't', 'y'
    };


    public DiscreteLogEquality() {
        if ( !initialized ) {
            initialize();
        }
    }

    // FIXME the resource manager, curve and other should be initialized on the applet class level
    public void initialize() {
        if ( initialized ) {
            return;
        }
        r = new BigNat(IndistinguishabilityApplet.curve.rBN.length(), JCSystem.MEMORY_TYPE_TRANSIENT_RESET, IndistinguishabilityApplet.rm);
        ch = new BigNat(IndistinguishabilityApplet.curve.rBN.length(), JCSystem.MEMORY_TYPE_TRANSIENT_RESET, IndistinguishabilityApplet.rm);
        G = new ECPoint(IndistinguishabilityApplet.curve);
        publicShare = new ECPoint(IndistinguishabilityApplet.curve);
        hashToCurvePoint = new ECPoint(IndistinguishabilityApplet.curve);
        partialDerivedShare = new ECPoint(IndistinguishabilityApplet.curve);
        com1 = new ECPoint(IndistinguishabilityApplet.curve);
        com2 = new ECPoint(IndistinguishabilityApplet.curve);
        userPoint = new ECPoint(IndistinguishabilityApplet.curve);
        tmpPoint = new ECPoint(IndistinguishabilityApplet.curve);
        M = new ECPoint(IndistinguishabilityApplet.curve);
        G.setW(SecP256r1.G, (short) 0, (short) SecP256r1.G.length);
        curveOrder = new BigNat(IndistinguishabilityApplet.curve.rBN.length(), JCSystem.MEMORY_TYPE_TRANSIENT_RESET, IndistinguishabilityApplet.rm);


        aBN = new BigNat(IndistinguishabilityApplet.curve.rBN.length(), JCSystem.MEMORY_TYPE_TRANSIENT_RESET, IndistinguishabilityApplet.rm);
        bBN = new BigNat(IndistinguishabilityApplet.curve.rBN.length(), JCSystem.MEMORY_TYPE_TRANSIENT_RESET, IndistinguishabilityApplet.rm);

        secretShare = new BigNat(IndistinguishabilityApplet.curve.rBN.length(), JCSystem.MEMORY_TYPE_PERSISTENT, IndistinguishabilityApplet.rm);

        initialized = true;
    }

    public void setShare(BigNat dkgSecretShare, ECPoint dkgPublicShare) {
        // this should also set the partial public key y_i, aka do some initialization
        secretShare.copy(dkgSecretShare);
        publicShare.copy(dkgPublicShare);
    }

    private void printBigNat(BigNat num) {
        num.copyToByteArray(tmp, (short) 0);
        for (short i = 0; i < 32; i ++ ) {
            System.out.print(String.format("%02x", tmp[i]));
        }
        System.out.println();
    }

    public void calculateModMult(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        // a.setValue((short) 1);
        IndistinguishabilityApplet.rng.nextBytes(tmp, (short) 0, (short) 32);
        aBN.fromByteArray(tmp, (short) 0, (short) 32);

        // b.setValue((short) 2);
        IndistinguishabilityApplet.rng.nextBytes(tmp, (short) 0, (short) 32);
        bBN.fromByteArray(tmp, (short) 0, (short) 32);

        printBigNat(aBN);
        printBigNat(bBN);
        printBigNat(IndistinguishabilityApplet.curve.rBN);
        aBN.modMult(bBN, IndistinguishabilityApplet.curve.rBN);
        printBigNat(aBN);
        aBN.copyToByteArray(apduBuffer, (short) 0);

        apdu.setOutgoingAndSend((short) 0, (short) 32);
    }

    /**
     * Implemented following the description from the publication:
     *     Fully Distributed Verifiable Random Functions and their Application to Decentralised Random Beacons
     *     Page 3. Definition 2.1
     *     link: https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=9581233
     *
     *     Instead of the multiplicative notation we use the additive one.
     */
    public short proveEq(ECPoint H, ECPoint pubkeyPoint, ECPoint partial, byte[] out) {
        // choose random r <- ZZ_q
        IndistinguishabilityApplet.rng.nextBytes(tmp, (short) 0, (short) 32);
        r.fromByteArray(tmp, (short) 0, (short) 32);
        // FIXME measure, whether the modding is necessary. The consequent point multiplication is possible either way.
        // r.mod(IndistinguishabilityApplet.curve.rBN);
        // FIXME implement rG via the co-processor, set r as private key and compute public key
        // compute com1 = rG
        com1.copy(G);
        com1.multiplication(r);
        // compute com2 = rH
        com2.copy(H);
        com2.multiplication(r);
        // compute ch <- H(g, h , x, y, com1, com2)
        short hashSize = hashCommitments(userPoint, pubkeyPoint, partial, com1, com2);
        ch.fromByteArray(tmp, (short) 0, hashSize);
        // compute res = r + secretShare * ch
        ch.modMult(secretShare, IndistinguishabilityApplet.curve.rBN);
        // res = r
        r.modAdd(ch, IndistinguishabilityApplet.curve.rBN);

        // return (ch, res) in out
        Util.arrayCopyNonAtomic(tmp, (short) 0, out, (short) 0, hashSize);
        short resSize = r.copyToByteArray(tmp, (short) 0);
        Util.arrayCopyNonAtomic(tmp, (short) 0, out, hashSize, resSize);
        return (short) (hashSize + resSize);
    }

    public short partialEval(byte[] userInput, short offset, short length, byte[] out, short outOffset) {
        if ( !IndistinguishabilityApplet.h2c.hash(userInput, offset, length, userPoint) ) {
            return (short) 0;
        }

        partialDerivedShare.copy(userPoint);
        partialDerivedShare.multiplication(secretShare);

        // calculate the proof
        short proofLength = proveEq2(userPoint, partialDerivedShare, out, outOffset);
        // and also send the actual derive salt share
        short encodedLength = partialDerivedShare.encode(out, (short) (outOffset + proofLength), false);

        return (short) (proofLength + encodedLength);
    }

    /**
     * Implemented following the description from the publication:
     *     Fully Distributed Verifiable Random Functions and their Application to Decentralised Random Beacons
     *     Page 3. Definition 2.1
     *     link: https://ieeexplore.ieee.org/stamp/stamp.jsp?tp=&arnumber=9581233
     *
     *     Instead of the multiplicative notation we use the additive one.
     *
     *     Params:
     *     G generator is implicit
     *     H is the user provided point H(x)
     *     vk_i is the publicShare given implicitly
     *     v_i is the derivation share
     *     r is the randomness, but generated inline
     */
    public short proveEq2(/*ECPoint G,*/ ECPoint H, /*ECPoint vk_i ,*/ ECPoint partialDerivedShare, /*r,*/ byte[] out, short outOffset) {
        // choose random r <- ZZ_q
        IndistinguishabilityApplet.rng.nextBytes(tmp, (short) 0, (short) 32);
        r.fromByteArray(tmp, (short) 0, (short) 32);
        // TODO measure, whether the modding is necessary. The consequent point multiplication is possible either way.
        // r.mod(IndistinguishabilityApplet.curve.rBN);
        // TODO implement rG via the co-processor, set r as private key and compute public key
        // compute com1 = rG
        com1.copy(G);
        com1.multiplication(r);
        // compute com2 = rH
        com2.copy(H);
        com2.multiplication(r);
        // compute ch <- H(g, h , x, y, com1, com2)
        short hashSize = hashCommitments2(/*ECPoint G,*/ H, /*publicShare,*/ partialDerivedShare, com1, com2);
        ch.fromByteArray(tmp, (short) 0, hashSize);
        // compute res = r + secretShare * ch
        ch.modMult(secretShare, IndistinguishabilityApplet.curve.rBN);
        // res = r
        r.modAdd(ch, IndistinguishabilityApplet.curve.rBN);

        // return (ch, res) in out
        Util.arrayCopyNonAtomic(tmp, (short) 0, out, (short) 0, hashSize);
        short resSize = r.copyToByteArray(tmp, (short) 0);
        Util.arrayCopyNonAtomic(tmp, (short) 0, out, hashSize, resSize);
        return (short) (hashSize + resSize);
    }

    private short hashCommitments2(/*ECPoint G,*/ ECPoint H, /* ECPoint X,*/ ECPoint Y, ECPoint com1, ECPoint com2) {
        hasher.reset();
        hasher.update(HASH_DLEQ_DOMAIN_SEPARATOR, (short) 0, (short) HASH_DLEQ_DOMAIN_SEPARATOR.length);

        // The curve generator is an implicit parameter
        short pointByteLen = G.getW(tmp, (short) 0);
        hasher.update(tmp, (short) 0, pointByteLen);

        pointByteLen = H.getW(tmp, (short) 0);
        hasher.update(tmp, (short) 0, pointByteLen);

        pointByteLen = publicShare.getW(tmp, (short) 0);
        hasher.update(tmp, (short) 0, pointByteLen);

        pointByteLen = Y.getW(tmp, (short) 0);
        hasher.update(tmp, (short) 0, pointByteLen);

        pointByteLen = com1.getW(tmp, (short) 0);
        hasher.update(tmp, (short) 0, pointByteLen);

        pointByteLen = com2.getW(tmp, (short) 0);
        hasher.doFinal(tmp, (short) 0, pointByteLen, tmp, (short) 0);

        return hasher.getLength();
    }

    /**
     * Hash to ZZq, where q is the curve order.
     * FIXME currenlty we do not use modulus to really fit in ZZq.
     *
     * @param H
     * @param X
     * @param Y
     // * @param k
     * @param out
     */
    private short hashCommitments(ECPoint H, ECPoint X, ECPoint Y, ECPoint com1, ECPoint com2) {
        hasher.reset();
        hasher.update(HASH_DLEQ_DOMAIN_SEPARATOR, (short) 0, (short) HASH_DLEQ_DOMAIN_SEPARATOR.length);

        // The curve generator is an implicit parameter
        short pointByteLen = G.getW(tmp, (short) 0);
        hasher.update(tmp, (short) 0, pointByteLen);

        pointByteLen = H.getW(tmp, (short) 0);
        hasher.update(tmp, (short) 0, pointByteLen);

        pointByteLen = X.getW(tmp, (short) 0);
        hasher.update(tmp, (short) 0, pointByteLen);

        pointByteLen = Y.getW(tmp, (short) 0);
        hasher.update(tmp, (short) 0, pointByteLen);

        pointByteLen = com1.getW(tmp, (short) 0);
        hasher.update(tmp, (short) 0, pointByteLen);

        pointByteLen = com2.getW(tmp, (short) 0);
        hasher.doFinal(tmp, (short) 0, pointByteLen, tmp, (short) 0);
        // short bigNatLen = k.copyToByteArray(tmp, (short) 0);
        // hasher.doFinal(k, (short) 0, bigNatLen, tmp, (short) 0);

        return hasher.getLength();
    }


    public short exampleProof(byte[] out) {
        // convert the ephemeral key to point and secretShare
        for (short i = 0; i < 32; i ++ ) {
            System.out.print(String.format("%02x", tmp[i]));
        }
        // G.multiplication(secretShare);
        System.out.println();
        short byteLength = IndistinguishabilityApplet.curve.disposablePub.getW(tmp, (short) 0);
        tmpPoint.setW(tmp, (short) 0, byteLength);

        return proveEq(userPoint, tmpPoint, M, out);
    }

    /**
     * The verification is not needed and thus not supported on the JavaCard
     */
    private void VerifyEq() throws ISOException {
        ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
    }
}
