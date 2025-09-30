package applet;

// Source: https://github.com/OpenCryptoProject/JCMathLib
import applet.jcmathlib.*;

import javacard.framework.*;
import javacard.security.*;
import javacardx.framework.util.*;

// import static applet.IndistinguishabilityApplet;

public class DiscreteLogEquality {
    public static ECCurve curve;
    // FIXME M is H actually :D
    public static ECPoint G, com1, com2, userPoint, M, tmpPoint;
    public static BigNat r, ch, tmpNum, secret;
    public static BigNat curveOrder;
    public static BigNat aBN, bBN;
    private byte[] tmp = new byte[128];
    public boolean initialized = false;
    public static RandomData rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
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
        // NOTE r for the protocol versus `r` as the curve order
        curve = new ECCurve(SecP256r1.p, SecP256r1.a, SecP256r1.b, SecP256r1.G, SecP256r1.r, SecP256r1.k, IndistinguishabilityApplet.rm);
        r = new BigNat(curve.rBN.length(), JCSystem.MEMORY_TYPE_TRANSIENT_RESET, IndistinguishabilityApplet.rm);
        ch = new BigNat(curve.rBN.length(), JCSystem.MEMORY_TYPE_TRANSIENT_RESET, IndistinguishabilityApplet.rm);
        G = new ECPoint(curve);
        com1 = new ECPoint(curve);
        com2 = new ECPoint(curve);
        userPoint = new ECPoint(curve);
        tmpPoint = new ECPoint(curve);
        M = new ECPoint(curve);
        G.setW(SecP256r1.G, (short) 0, (short) SecP256r1.G.length);
        curveOrder = new BigNat(curve.rBN.length(), JCSystem.MEMORY_TYPE_TRANSIENT_RESET, IndistinguishabilityApplet.rm);


        aBN = new BigNat(curve.rBN.length(), JCSystem.MEMORY_TYPE_TRANSIENT_RESET, IndistinguishabilityApplet.rm);
        bBN = new BigNat(curve.rBN.length(), JCSystem.MEMORY_TYPE_TRANSIENT_RESET, IndistinguishabilityApplet.rm);

        ECPrivateKey privKey = curve.disposablePriv;
        secret = new BigNat(curve.rBN.length(), JCSystem.MEMORY_TYPE_TRANSIENT_RESET, IndistinguishabilityApplet.rm);
        short byteLength = privKey.getS(tmp, (short) 0);
        secret.fromByteArray(tmp, (short) 0, byteLength);
        secret.mod(curve.rBN);

        initialized = true;
    }

    private void printBigNat(BigNat num) {
        num.copyToByteArray(tmp, (short) 0);
        for (short i = 0; i < 32; i ++ ) {
            System.out.print(String.format("%02x", tmp[i]));
        }
        System.out.println();
    }

    public void calculateModMult() {
        // a.setValue((short) 1);
        rng.generateData(tmp, (short) 0, (short) 32);
        aBN.fromByteArray(tmp, (short) 0, (short) 32);

        // b.setValue((short) 2);
        rng.generateData(tmp, (short) 0, (short) 32);
        bBN.fromByteArray(tmp, (short) 0, (short) 32);

        printBigNat(aBN);
        printBigNat(bBN);
        printBigNat(curve.rBN);
        aBN.modMult(bBN, curve.rBN);
        printBigNat(aBN);
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
        rng.generateData(tmp, (short) 0, (short) 32);
        r.fromByteArray(tmp, (short) 0, (short) 32);
        // FIXME measure, whether the modding is necessary. The consequent point multiplication is possible either way.
        // r.mod(curve.rBN);
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
        // compute res = r + secret * ch
        ch.modMult(secret, curve.rBN);
        // res = r
        r.modAdd(ch, curve.rBN);

        // return (ch, res) in out
        Util.arrayCopyNonAtomic(tmp, (short) 0, out, (short) 0, hashSize);
        short resSize = r.copyToByteArray(tmp, (short) 0);
        Util.arrayCopyNonAtomic(tmp, (short) 0, out, hashSize, resSize);
        return (short) (hashSize + resSize);
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
        MessageDigest hasher = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
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
        // FIXME set this curve elsewhere and reference it as _the curve_
        ECPrivateKey privKey = curve.disposablePriv;
        ECPublicKey pubKey = curve.disposablePub;

        // convert the ephemeral key to point and secret
        for (short i = 0; i < 32; i ++ ) {
            System.out.print(String.format("%02x", tmp[i]));
        }
        // G.multiplication(secret);
        System.out.println();
        short byteLength = pubKey.getW(tmp, (short) 0);
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
