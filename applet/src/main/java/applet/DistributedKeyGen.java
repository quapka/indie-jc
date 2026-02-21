package applet;

import applet.jcmathlib.BigNat;
import applet.jcmathlib.SecP256r1;
import applet.jcmathlib.ECPoint;
import applet.jcmathlib.ECCurve;

import javacard.framework.*;
import javacard.framework.Util;
import javacard.security.RandomData;
import javacard.security.*;
import javacardx.framework.util.*;

public class DistributedKeyGen {
    // FIXME 
    // private byte maxParties = 2;
    public byte threshold;
    public byte nParties;
    public byte partyID; // partyIndex + 1
    public byte partyIndex; // partyID - 1 
    private RandomData rng;

    private byte coeffSize = 32;
    // public byte[][] aCoeffs, bCoeffs;
    public BigNat[] aCoeffs, bCoeffs, aShares, bShares, otherAShares, otherBShares;
    public BigNat xShare;
    public ECPoint[] cPoints, aPoints;
    public byte nCoeffs;
    // public byte[maxParties][coeffSize] aCoeffs, bCoeffs;
    public static ECCurve curve;
    // G is the curve generator and H is another point H = hG, with the h being unknown.
    public static ECPoint G, H,tmpPointA, tmpPointB, tmpPointC, groupKey;
    // FIXME rewrite tmpNum to tmpBN
    public static BigNat r, ch, tmpNum, secret;
    public static BigNat curveOrder;
    // NOTE evaluation should hold up to 14 parties
    private byte[] tmp = new byte[512];
    boolean initialized = false;

    public DistributedKeyGen(byte threshold, byte nParties) {
        this.threshold = threshold;
        this.nParties = nParties;

        if ( !initialized ) {
            initialize();
        }
    }

    // FIXME the resource manager, curve and other should be initialized on the applet class level
    // FIXME should be shared across other functionalities.
    public void initialize() {
        if ( initialized ) {
            return;
        }
        // rm = new ResourceManager((short) 256);
        // NOTE r for the protocol versus `r` as the curve order
        curve = new ECCurve(SecP256r1.p, SecP256r1.a, SecP256r1.b, SecP256r1.G, SecP256r1.r, SecP256r1.k, IndistinguishabilityApplet.rm);
        rng = RandomData.getInstance(RandomData.ALG_KEYGENERATION);
        r = new BigNat(curve.rBN.length(), JCSystem.MEMORY_TYPE_TRANSIENT_RESET, IndistinguishabilityApplet.rm);
        ch = new BigNat(curve.rBN.length(), JCSystem.MEMORY_TYPE_TRANSIENT_RESET, IndistinguishabilityApplet.rm);
        tmpNum = new BigNat(curve.rBN.length(), JCSystem.MEMORY_TYPE_TRANSIENT_RESET, IndistinguishabilityApplet.rm);
        G = new ECPoint(curve);
        tmpPointA = new ECPoint(curve);
        tmpPointB = new ECPoint(curve);
        tmpPointC = new ECPoint(curve);
        groupKey = new ECPoint(curve);
        H = new ECPoint(curve);

        G.setW(SecP256r1.G, (short) 0, (short) SecP256r1.G.length);

        // FIXME H dleq should be random and unknown to the attacker, use the public point for Musig2/epochs?
        H.setW(SecP256r1.G, (short) 0, (short) SecP256r1.G.length);
        tmpNum.setValue((byte) 0x02);
        H.multiplication(tmpNum);
        
        ECPrivateKey privKey = curve.disposablePriv;
        secret = new BigNat(curve.rBN.length(), JCSystem.MEMORY_TYPE_TRANSIENT_RESET, IndistinguishabilityApplet.rm);

        aCoeffs = new BigNat[nParties];
        bCoeffs = new BigNat[nParties];
        aShares = new BigNat[nParties];
        bShares = new BigNat[nParties];
        otherAShares = new BigNat[nParties];
        otherBShares = new BigNat[nParties];

        cPoints = new ECPoint[nParties * nParties];
        aPoints = new ECPoint[nParties * nParties];

        this.nCoeffs = nParties;

        for (short i = 0; i < nCoeffs; i++) {
            // FIXME load from persistent to transient upon select to speed up?
            // FIXME generate coeffs as a hash of some seed to avoid persistent memory
            aCoeffs[i] = new BigNat(curve.rBN.length(), JCSystem.MEMORY_TYPE_PERSISTENT, IndistinguishabilityApplet.rm);
            bCoeffs[i] = new BigNat(curve.rBN.length(), JCSystem.MEMORY_TYPE_PERSISTENT, IndistinguishabilityApplet.rm);

            aShares[i] = new BigNat(curve.rBN.length(), JCSystem.MEMORY_TYPE_TRANSIENT_RESET, IndistinguishabilityApplet.rm);
            bShares[i] = new BigNat(curve.rBN.length(), JCSystem.MEMORY_TYPE_TRANSIENT_RESET, IndistinguishabilityApplet.rm);

            otherAShares[i] = new BigNat(curve.rBN.length(), JCSystem.MEMORY_TYPE_PERSISTENT, IndistinguishabilityApplet.rm);
            otherBShares[i] = new BigNat(curve.rBN.length(), JCSystem.MEMORY_TYPE_PERSISTENT, IndistinguishabilityApplet.rm);

            for (short j = 0; j < nParties; j++) {
                short index = (short) (j * nParties + i);
                cPoints[index] = new ECPoint(curve);
                cPoints[index].setW(SecP256r1.G, (short) 0, (short) SecP256r1.G.length);
                aPoints[index] = new ECPoint(curve);
                aPoints[index].setW(SecP256r1.G, (short) 0, (short) SecP256r1.G.length);
            }
        }

        initialized = true;
    }

    /**
     * Secure Distributed Key Generation for Discrete-Log Based Cryptosystems
     * Fig. 2 1.a)
     */
    // private void generateCoefficientsAndShares(byte[] buffer, short offset, short length) {
    public void generateCoefficientsAndShares() {

        // generate coefficients
        for (short i = 0; i < nParties; i++) {
            rng.nextBytes(tmp, (short) 0, (short) 32);
            aCoeffs[i].fromByteArray(tmp, (short) 0, (short) 32);
            aCoeffs[i].mod(curve.rBN);

            rng.nextBytes(tmp, (short) 0, (short) 32);
            bCoeffs[i].fromByteArray(tmp, (short) 0, (short) 32);
            bCoeffs[i].mod(curve.rBN);
        }

        // calculated the to-be broadcasted points
        for (short k = 0; k < nCoeffs; k++) {
            short index = (short) ((partyIndex * nParties) + k);
            G.setW(SecP256r1.G, (short) 0, (short) SecP256r1.G.length);
            // a_ik * G
            cPoints[index].copy(G);
            cPoints[index].multiplication(aCoeffs[k]);

            // FIXME H = 2G for now
            H.setW(SecP256r1.G, (short) 0, (short) SecP256r1.G.length);
            tmpNum.setValue((byte) 0x02);
            H.multiplication(tmpNum);

            // b_ik * H
            tmpPointA.copy(H);
            tmpPointA.multiplication(bCoeffs[k]);
            // C_ik = a_ik * G + b_ik * H
            cPoints[index].add(tmpPointA);
        }
        evaluateShares();
    }

    public void evaluateShares() {
        for (short i = 0; i < nParties; i++) {
            // NOTE the evaluation points are the partyIDs not the partyIndeces
            tmpNum.setValue((short) (i + 1));
            evaluatePolynomial(aShares[i], tmpNum, aCoeffs, nCoeffs);
            evaluatePolynomial(bShares[i], tmpNum, bCoeffs, nCoeffs);
        }
    }

    public void getABCoeffs(byte[] out) {
        for (short i = 0; i < nParties; i++) {
            aCoeffs[i].copyToByteArray(tmp, (short) 0);
            Util.arrayCopyNonAtomic(tmp, (short) 0, out, (short) (i * 32), (short) 32);
        }

        for (short i = 0; i < nParties; i++) {
            bCoeffs[i].copyToByteArray(tmp, (short) 0);
            Util.arrayCopyNonAtomic(tmp, (short) 0, out, (short) (i * 32 + 64), (short) 32);
        }
    }

    /**
     * Evaluate the polynomial f given by the coefficients a_i at  value.
     * Using Horner's rule, https://en.wikipedia.org/wiki/Polynomial_evaluation
     * Possibly, consider different versions.
     */
    private void evaluatePolynomial(BigNat result, BigNat value, BigNat[] coefficients, short nCoeffs) {
        result.copy(coefficients[(short) (nCoeffs - 1)]);

        for (short i = (short) (nCoeffs - 1); i > 0; i--) {
            result.modMult(value, curve.rBN);
            result.modAdd(coefficients[(short) (i - 1)], curve.rBN);
        }
    }

    public void setCPoints(byte fromPartyID, byte[] cPointsData, short offset) {
        byte fromPartyIndex = (byte) (fromPartyID - 1);
        short pubKeySize = 65;

        for (short i = 0; i < nParties; i++) {
            short from = (short) (i * pubKeySize + offset);

            short index = (short) (fromPartyIndex * nParties + i);
            cPoints[index].setW(cPointsData, from, pubKeySize);
        }
    }

    public short getShares(byte forPartyID, byte[] out, short offset) {
        System.out.println(String.format("Me: '%d' supposed to send to '%d'", partyIndex, forPartyID));
        // don't leak our own shares
        if ( forPartyID == partyID ) {
            return (short) 0;
        }
        byte forPartyIndex = (byte) (forPartyID - 1);
        evaluateShares();
        short outSize = aShares[forPartyIndex].copyToByteArray(out, offset);
        outSize = (short) (outSize + bShares[forPartyIndex].copyToByteArray(out, (short) (offset + outSize)));

        return outSize;
    }

    /**
     * Secure Distributed Key Generation for Discrete-Log Based Cryptosystems
     * Fig. 2 1.b)
     *
     * shares are s_ij and s'_ij
     */
    public boolean verifyShares(byte fromPartyID) { //, byte[] out) {
        // Skip verifying our own shares
        byte fromPartyIndex = (byte) (fromPartyID - 1);
        if ( fromPartyID == partyID ) {
            return false;
        }
        G.setW(SecP256r1.G, (short) 0, (short) SecP256r1.G.length);

        H.setW(SecP256r1.G, (short) 0, (short) SecP256r1.G.length);
        tmpNum.setValue((byte) 0x02);
        H.multiplication(tmpNum);

        // s'_ij * H
        tmpPointB.copy(H);
        tmpPointB.multiplication(otherBShares[fromPartyIndex]);

        // s_ij * G + s'_ij * H
        tmpPointA.copy(G);
        tmpPointA.multAndAdd(otherAShares[fromPartyIndex], tmpPointB);

        short k = 0;
        short index = (short) (fromPartyIndex * nParties + k);
        tmpPointC.copy(cPoints[index]);

        for (k = 1; k < nParties; k++) {
            // C_ik
            index = (short) (fromPartyIndex * nParties + k);
            tmpPointB.copy(cPoints[index]);
            // j
            tmpNum.setValue(partyID);
            // k
            ch.setValue(k);
            // j^k
            tmpNum.modExp(ch, curve.rBN);
            // j^k * C_ik
            tmpPointB.multiplication(tmpNum);
            // aggregate
            tmpPointC.add(tmpPointB);
        }

        return tmpPointA.isEqual(tmpPointC);
    }

    public short getAPoints(byte[] out) {
        short keySize = 65;
        // FIXME We assume all parties are in QUAL
        short k = 0;
        for (; k < nCoeffs; k++) {
            tmpPointA.setW(SecP256r1.G, (short) 0, (short) SecP256r1.G.length);
            tmpPointA.multiplication(aCoeffs[k]);

            tmpPointA.encode(out, (short) (keySize * k), false);
            // save the computed point to self
            short index = (short) (partyIndex * nParties + k);
            aPoints[index].copy(tmpPointA);
        }
        return (short) (keySize * k);
    }

    public void setAPoints(byte fromPartyID, byte[] aPointsData, short offset) {
        short fromPartyIndex = (short) (fromPartyID - 1);
        short pubKeySize = 65;

        for (short k = 0; k < nCoeffs; k++) {
            short fromOffset = (short) (k * pubKeySize + offset);

            short index = (short) (fromPartyIndex * nParties + k);
            aPoints[index].setW(aPointsData, fromOffset, pubKeySize);
        }
    }

    public boolean verifyAPoints() {
        for (short i = 0; i < nParties; i++) {
            // FIXME cache (i * nParties)
            if ( i == partyIndex ) {
                // skip self
                continue;
            }
            // s_ij * G
            tmpPointB.setW(SecP256r1.G, (short) 0, (short) SecP256r1.G.length);
            tmpPointB.multiplication(otherAShares[i]);

            short k = 0;
            short index = (short) (i * nParties + k);
            tmpPointC.copy(aPoints[index]);

            for (k = 1; k < nParties; k++) {
                index = (short) (i * nParties + k);
                // A_ik
                tmpPointA.copy(aPoints[index]);
                // j
                tmpNum.setValue(partyID);
                // k
                ch.setValue(k);
                // j^k
                tmpNum.modExp(ch, curve.rBN);
                // j^k * A_ik 
                tmpPointA.multiplication(tmpNum);
                // aggregate
                tmpPointC.add(tmpPointA);
            }
        }

        return tmpPointC.isEqual(tmpPointB);
    }

    public void computeY() {
        groupKey.copy(aPoints[0]);
        // groupKey.add(aPoints[2]);
        for (short i = 1; i < nParties; i++) {
            short index = (short) (i * nParties);
            groupKey.add(aPoints[index]);
        }
    }

    public short getGroupKey(byte[] out, short offset) {
        return groupKey.encode(out, offset, false);
    }

    public void computeXShare() {
        // for all parties j in QUAL (we assume its all parties for now), sum s_ji
        // this in principle should equal sum otherAShares, but it's missing self A share

        // start with our own share
        tmpNum.copy(aShares[partyIndex]);
        for (short j = 0; j < nParties; j++) {
            if ( j == partyIndex ) {
                // skip,otherAShares[j] should be empty
                continue;
            }
            tmpNum.modAdd(otherAShares[j], curve.rBN);
        }
    }
}
