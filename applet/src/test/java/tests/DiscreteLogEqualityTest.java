package tests;

import java.util.*;

import javacard.security.*;
import javacard.security.RandomData;
import javacard.framework.JCSystem;

import applet.jcmathlib.*;
import applet.DiscreteLogEquality;
import applet.Consts;

import cz.muni.fi.crocs.rcard.client.CardType;

import org.junit.Assert;
import org.junit.jupiter.api.*;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.jce.spec.ECParameterSpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.math.BigInteger;
import java.util.*;

public class DiscreteLogEqualityTest extends BaseTest {
    public static ECCurve curve;
    public static ECPoint Generator;
    public static BigInteger x;
    public static BigInteger y;
    private static final int SIGNUM_POSITIVE = 1;

    public static ECParameterSpec CURVE_SPEC = null;
    public static byte[] CURVE_P = SecP256r1.p;
    public static byte[] CURVE_R = SecP256r1.r;
    public static byte[] CURVE_A = SecP256r1.a;
    public static byte[] CURVE_B = SecP256r1.b;
    public static byte[] CURVE_G = SecP256r1.G;
    public static short CURVE_K = SecP256r1.k;

    public DiscreteLogEqualityTest() throws Exception {
        super();

        curve = new ECCurve.Fp(new BigInteger(1, CURVE_P), new BigInteger(1, CURVE_A), new BigInteger(1, CURVE_B));
        BigInteger x = new BigInteger(1, Arrays.copyOfRange(CURVE_G, 1, CURVE_G.length / 2 + 1));
        BigInteger y = new BigInteger(1, Arrays.copyOfRange(CURVE_G, 1 + CURVE_G.length / 2, CURVE_G.length));
        Generator = curve.createPoint(x, y);
        CURVE_SPEC = new ECParameterSpec(curve, Generator, new BigInteger(1, CURVE_R), BigInteger.valueOf(CURVE_K));
    }

    /**
     * Generate a random point on the chosen secp256r1 curve
     */
    public ECPoint randomPoint() {
        RandomData rng = RandomData.getInstance(RandomData.ALG_KEYGENERATION);
        byte[] buffer = new byte[32];
        rng.generateData(buffer, (short) 0, (short) 32);

        BigInteger scalar = new BigInteger(SIGNUM_POSITIVE, Arrays.copyOfRange(buffer, 0, 32));

        return Generator.multiply(scalar);
    }

    private ECPoint getCardVerificationPubkey() throws Exception {
        // FIXME hide this in a method
        CommandAPDU cmd = new CommandAPDU(Consts.CLA.INDIE, Consts.INS.GET_VERIFICATION_PUBKEY, 0x00, 0x00);
        ResponseAPDU responseAPDU = connect().transmit(cmd);
        // FIXME add asserts
        byte[] pubKeyData = responseAPDU.getData();
        BigInteger xCoord = new BigInteger(SIGNUM_POSITIVE, Arrays.copyOfRange(pubKeyData, 1, 33));
        BigInteger yCoord = new BigInteger(SIGNUM_POSITIVE, Arrays.copyOfRange(pubKeyData, 33, 65));
        ECPoint verPubkeyPoint = curve.createPoint(xCoord, yCoord);
        return verPubkeyPoint;
    }

    // FIXME remove the computeModMult test
    @Test
    public void computeModMult() throws Exception {
        CommandAPDU computeModMultCmd = new CommandAPDU(Consts.CLA.DEBUG, Consts.INS.COMPUTE_MOD_MULT, 0x00, 0x00);
        ResponseAPDU responseAPDU = connect().transmit(computeModMultCmd);
        Assert.assertEquals(0x9000, responseAPDU.getSW());
    }

    // FIXME
    @Test
    public void testComputingDleqProof() throws Exception {
        ECPoint verPubkeyPoint = getCardVerificationPubkey();
        // There is not hash to curve calculation, simply a random point is
        // generated directly
        ECPoint hashedToCurvePoint = randomPoint();

        byte[] encoded = hashedToCurvePoint.getEncoded(false);
        CommandAPDU getProofCmd = new CommandAPDU(Consts.CLA.INDIE, Consts.INS.GET_EXAMPLE_PROOF, 0x00, 0x00, encoded);

        // System.out.println(String.format("Encoded: %d", encoded.length));
        // for (short i = 0; i < encoded.length; i++) {
        //     System.out.print(String.format("%02x", encoded[i]));
        // }

        System.out.println();
        ResponseAPDU responseAPDU = connect().transmit(getProofCmd);

        System.out.println(String.format("ResponseAPDU from example proof: %d", responseAPDU.getData().length));
        for (short i = 0; i < responseAPDU.getData().length; i++) {
            System.out.print(String.format("%02x", responseAPDU.getData()[i]));
        }

        byte[] proof = Arrays.copyOfRange(responseAPDU.getData(), 0, 64);
        byte[] derivedPointData = Arrays.copyOfRange(responseAPDU.getData(), 64, 64 + 65);
        BigInteger xCoord = new BigInteger(SIGNUM_POSITIVE, Arrays.copyOfRange(derivedPointData, 1, 33));
        BigInteger yCoord = new BigInteger(SIGNUM_POSITIVE, Arrays.copyOfRange(derivedPointData, 33, 65));
        ECPoint derivedPoint = curve.createPoint(xCoord, yCoord);

        Assertions.assertTrue(VerifyEq(Generator, hashedToCurvePoint, verPubkeyPoint, derivedPoint, proof));
    }

    /**
     * Implemented following the description from the publication:
     *     Fully Distributed Verifiable Random Functions
     *     and their Application to Decentralised Random Beacons
     */
    public boolean VerifyEq(ECPoint G, ECPoint H, ECPoint X, ECPoint Y, byte[] proof) throws NoSuchAlgorithmException {
        byte[] chVerifyData = Arrays.copyOfRange(proof, 0, 32);
        BigInteger chVerify = new BigInteger(SIGNUM_POSITIVE, chVerifyData);
        BigInteger resVerify = new BigInteger(SIGNUM_POSITIVE, Arrays.copyOfRange(proof, 32, 64));

        ECPoint com1Verify = G.multiply(resVerify).add(X.multiply(chVerify).negate());
        ECPoint com2Verify = H.multiply(resVerify).add(Y.multiply(chVerify).negate());
        byte[] digest = hashCommitments(G, H, X, Y, com1Verify, com2Verify);

        return Arrays.equals(chVerifyData, digest);
    }

    public byte[] hashCommitments(ECPoint G, ECPoint H, ECPoint X, ECPoint Y, ECPoint com1, ECPoint com2) throws NoSuchAlgorithmException{
        MessageDigest hasher = MessageDigest.getInstance("SHA-256");
        hasher.update(DiscreteLogEquality.HASH_DLEQ_DOMAIN_SEPARATOR);
        hasher.update(G.getEncoded(false));
        hasher.update(H.getEncoded(false));
        hasher.update(X.getEncoded(false));
        hasher.update(Y.getEncoded(false));
        hasher.update(com1.getEncoded(false));
        hasher.update(com2.getEncoded(false));

        return hasher.digest();
    }

}
