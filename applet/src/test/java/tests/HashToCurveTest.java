package test;

import java.lang.IllegalArgumentException;
import java.security.MessageDigest;
import java.util.Arrays;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.ECFieldElement;
import java.security.NoSuchAlgorithmException;
import java.math.BigInteger;

// import javacard.framework.ISOException;
// import javacard.framework.JCSystem;
// import javacard.framework.Util;
// import javacard.security.MessageDigest;
// import applet.jcmathlib.*;

// Source: https://github.com/crocs-muni/JCMint/blob/main/applet/src/main/java/jcmint/HashToCurve.java
public class HashToCurveTest {
    private static ECCurve curve;

    private BigInteger ZERO = new BigInteger("0");
    private BigInteger TWO = new BigInteger("2");

    public static final byte[] H2C_DOMAIN_SEPARATOR = {
        (byte) 0x53, (byte) 0x65, (byte) 0x63, (byte) 0x70,
        (byte) 0x32, (byte) 0x35, (byte) 0x36, (byte) 0x6b,
        (byte) 0x31, (byte) 0x5f, (byte) 0x48, (byte) 0x61,
        (byte) 0x73, (byte) 0x68, (byte) 0x54, (byte) 0x6f,
        (byte) 0x43, (byte) 0x75, (byte) 0x72, (byte) 0x76,
        (byte) 0x65, (byte) 0x5f, (byte) 0x43, (byte) 0x61,
        (byte) 0x73, (byte) 0x68, (byte) 0x75, (byte) 0x5f
    };
    private MessageDigest hasher;

    private byte[] prefixBuffer = new byte[36];

    public HashToCurveTest(ECCurve curve) throws NoSuchAlgorithmException {
        this.curve = curve;
        this.hasher = MessageDigest.getInstance("SHA-256");
    }

    public ECPoint digest(byte[] data) {

        prefixBuffer[32] = 0x00;
        prefixBuffer[33] = 0x00;
        prefixBuffer[34] = 0x00;
        prefixBuffer[35] = 0x00;

        hasher.reset();
        hasher.update(H2C_DOMAIN_SEPARATOR, (short) 0, (short) H2C_DOMAIN_SEPARATOR.length);
        byte[] digest = hasher.digest(data);

        for (int i = 0; i < 32; i++ ){
            prefixBuffer[i] = digest[i];
        }
        ECPoint point = curve.getInfinity();

        for (short counter = 0; counter < (short) 256; ++counter) {
            System.out.println(counter);

            hasher.reset();
            prefixBuffer[32] = (byte) (counter & 0xff);
            digest = hasher.digest(prefixBuffer);

            try {
                point = recoverPoint(new BigInteger(1, digest));
                break;
            } catch (IllegalArgumentException e) {
                continue;
            }
        }

        if  ( (point.getYCoord().toBigInteger().mod(TWO).compareTo(ZERO) != 0) ) {
            point = point.negate();
        }

        return point;
    }

    public ECPoint recoverPoint(BigInteger x) {
        ECFieldElement xField = curve.fromBigInteger(x);

        // Compute RHS of the curve equation: y^2 = x^3 + ax + b
        ECFieldElement rhs = xField.square()      // x^2
                                   .multiply(xField) // x^3
                                   .add(curve.getA().multiply(xField)) // + ax
                                   .add(curve.getB()); // + b

        ECFieldElement yField = rhs.sqrt();

        if (yField == null) {
            throw new IllegalArgumentException("Invalid x coordinate: no point exists on curve");
        }

        return curve.createPoint(x, yField.toBigInteger());
    }
}
