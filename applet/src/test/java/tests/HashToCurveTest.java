package tests;

import java.lang.IllegalArgumentException;
import java.security.MessageDigest;
import java.util.Arrays;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.ECFieldElement;
import java.security.NoSuchAlgorithmException;
import java.math.BigInteger;
import org.junit.Assert;

// import javacard.framework.ISOException;
// import javacard.framework.JCSystem;
// import javacard.framework.Util;
// import javacard.security.MessageDigest;
// import applet.jcmathlib.*;

// Source: https://github.com/crocs-muni/JCMint/blob/main/applet/src/main/java/jcmint/HashToCurve.java
public class HashToCurveTest {
    private static ECCurve curve;

    private BigInteger ZERO = new BigInteger("0");
    private BigInteger ONE = new BigInteger("1");
    private BigInteger TWO = new BigInteger("2");
    private BigInteger THREE = new BigInteger("3");
    private BigInteger TEN = new BigInteger("10");

    public static final byte[] H2C_DOMAIN_SEPARATOR = {
        (byte) 0x53, (byte) 0x65, (byte) 0x63, (byte) 0x70,
        (byte) 0x32, (byte) 0x35, (byte) 0x36, (byte) 0x6b,
        (byte) 0x31, (byte) 0x5f, (byte) 0x48, (byte) 0x61,
        (byte) 0x73, (byte) 0x68, (byte) 0x54, (byte) 0x6f,
        (byte) 0x43, (byte) 0x75, (byte) 0x72, (byte) 0x76,
        (byte) 0x65, (byte) 0x5f, (byte) 0x43, (byte) 0x61,
        (byte) 0x73, (byte) 0x68, (byte) 0x75, (byte) 0x5f
    };

    // RFC 9380 P256_XMD:SHA-256_SSWU_RO_ test vector DST
    // From RFC 9380 Appendix J.1.1
    public static final byte[] RFC9380_DST = "QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_".getBytes();

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

    /**
     * RFC 9380: expand_message_xmd for SHA-256
     * Expands a message to a uniform byte string of specified length
     */
    private byte[] expandMessageXmd(byte[] msg, byte[] dst, int lenInBytes) throws NoSuchAlgorithmException {
        int ell = (lenInBytes + 31) / 32; // ceil(len_in_bytes / 32)

        // DST_prime = DST || I2OSP(len(DST), 1)
        byte[] dstPrime = new byte[dst.length + 1];
        System.arraycopy(dst, 0, dstPrime, 0, dst.length);
        dstPrime[dst.length] = (byte) dst.length;

        // Z_pad = I2OSP(0, 64) - 64 zero bytes for SHA-256 block size
        byte[] zPad = new byte[64];

        // msg_prime = Z_pad || msg || I2OSP(len_in_bytes, 2) || I2OSP(0, 1) || DST_prime
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        md.update(zPad);
        md.update(msg);
        md.update(new byte[]{(byte) (lenInBytes >> 8), (byte) (lenInBytes & 0xFF)});
        md.update(new byte[]{0});
        md.update(dstPrime);
        byte[] b0 = md.digest();

        // b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
        md.reset();
        md.update(b0);
        md.update(new byte[]{1});
        md.update(dstPrime);
        byte[] b1 = md.digest();

        byte[] uniformBytes = new byte[lenInBytes];
        int copied = Math.min(32, lenInBytes);
        System.arraycopy(b1, 0, uniformBytes, 0, copied);
        int outPos = copied;

        byte[] biPrev = b1;
        for (int i = 2; i <= ell && outPos < lenInBytes; i++) {
            // XOR b_0 with b_{i-1}
            byte[] xorResult = new byte[32];
            for (int j = 0; j < 32; j++) {
                xorResult[j] = (byte) (b0[j] ^ biPrev[j]);
            }

            // b_i = H(strxor(b_0, b_{i-1}) || I2OSP(i, 1) || DST_prime)
            md.reset();
            md.update(xorResult);
            md.update(new byte[]{(byte) i});
            md.update(dstPrime);
            byte[] bi = md.digest();

            copied = Math.min(32, lenInBytes - outPos);
            System.arraycopy(bi, 0, uniformBytes, outPos, copied);
            outPos += copied;

            biPrev = bi;
        }

        return uniformBytes;
    }

    /**
     * RFC 9380: Simplified SWU map for P-256
     * Maps a field element u to a point on the curve
     */
    private ECPoint mapToSswu(BigInteger u) {
        BigInteger p = curve.getField().getCharacteristic();
        BigInteger A = curve.getA().toBigInteger();
        BigInteger B = curve.getB().toBigInteger();

        // Z = -10 for P-256
        BigInteger Z = p.subtract(TEN);

        // tv1 = u^2
        BigInteger uSq = u.modPow(TWO, p);

        // tv1 = Z * u^2
        BigInteger tv1 = Z.multiply(uSq).mod(p);

        // tv2 = tv1^2 = Z^2 * u^4
        BigInteger tv2 = tv1.modPow(TWO, p);

        // tv2 = tv2 + tv1 = Z^2 * u^4 + Z * u^2
        tv2 = tv2.add(tv1).mod(p);

        // tv2 = inv0(tv2)
        BigInteger tv2Inv;
        if (tv2.equals(ZERO)) {
            tv2Inv = ZERO;
        } else {
            tv2Inv = tv2.modInverse(p);
        }

        // x1 = (-B / A) * (1 + tv2)
        // For P-256: A = -3, B = curve.getB()
        // -B/A = B/3
        BigInteger x1 = B.multiply(THREE.modInverse(p)).mod(p);
        x1 = x1.multiply(ONE.add(tv2Inv)).mod(p);

        // If tv2 == 0, set x1 = B / (Z * A)
        if (tv2.equals(ZERO)) {
            BigInteger denom = Z.multiply(A).mod(p);
            x1 = B.multiply(denom.modInverse(p)).mod(p);
        }

        // gx1 = x1^3 + A * x1 + B
        BigInteger gx1 = x1.modPow(THREE, p).add(A.multiply(x1)).add(B).mod(p);

        // x2 = Z * u^2 * x1
        BigInteger x2 = Z.multiply(uSq).multiply(x1).mod(p);

        // gx2 = x2^3 + A * x2 + B
        BigInteger gx2 = x2.modPow(THREE, p).add(A.multiply(x2)).add(B).mod(p);

        // Choose x and compute y
        BigInteger x, y;
        if (isSquare(gx1, p)) {
            x = x1;
            y = modSqrt(gx1, p);
        } else {
            x = x2;
            y = modSqrt(gx2, p);
        }

        // Ensure sgn0(u) == sgn0(y)
        // sgn0 returns 1 if odd (negative), 0 if even (positive)
        // For prime fields, sgn0(x) = x mod 2
        int sgn0_u = u.mod(TWO).intValue();
        int sgn0_y = y.mod(TWO).intValue();
        if (sgn0_u != sgn0_y) {
            y = p.subtract(y);
        }

        return curve.createPoint(x, y);
    }

    /**
     * Check if a value is a quadratic residue (square) modulo p
     */
    private boolean isSquare(BigInteger x, BigInteger p) {
        if (x.equals(ZERO)) return true;
        // Euler's criterion: x^((p-1)/2) == 1 (mod p)
        BigInteger exp = p.subtract(ONE).divide(TWO);
        return x.modPow(exp, p).equals(ONE);
    }

    /**
     * Compute modular square root using Tonelli-Shanks algorithm
     */
    private BigInteger modSqrt(BigInteger n, BigInteger p) {
        if (!isSquare(n, p)) {
            throw new IllegalArgumentException("Not a quadratic residue");
        }

        // For P-256, p ≡ 3 (mod 4), so we can use the simpler formula
        // y = n^((p+1)/4) mod p
        if (p.mod(new BigInteger("4")).equals(THREE)) {
            return n.modPow(p.add(ONE).divide(new BigInteger("4")), p);
        }

        // General Tonelli-Shanks algorithm
        BigInteger q = p.subtract(ONE);
        BigInteger s = ZERO;
        while (q.mod(TWO).equals(ZERO)) {
            q = q.divide(TWO);
            s = s.add(ONE);
        }

        if (s.equals(ONE)) {
            return n.modPow(p.add(ONE).divide(new BigInteger("4")), p);
        }

        BigInteger z = TWO;
        while (isSquare(z, p)) {
            z = z.add(ONE);
        }

        BigInteger c = z.modPow(q, p);
        BigInteger r = n.modPow(q.add(ONE).divide(TWO), p);
        BigInteger t = n.modPow(q, p);
        BigInteger m = s;

        while (!t.equals(ONE)) {
            BigInteger tt = t;
            BigInteger i = ZERO;
            while (!tt.equals(ONE)) {
                tt = tt.modPow(TWO, p);
                i = i.add(ONE);
            }

            BigInteger exp = TWO.modPow(m.subtract(i).subtract(ONE), p.subtract(ONE));
            BigInteger b = c.modPow(exp, p);
            r = r.multiply(b).mod(p);
            c = b.modPow(TWO, p);
            t = t.multiply(c).mod(p);
            m = i;
        }

        return r;
    }

    /**
     * RFC 9380 hash_to_curve for P-256 using Simplified SWU
     */
    public ECPoint hashToCurveRfc9380(byte[] msg, int offset, int length) throws NoSuchAlgorithmException {
        // Extract the relevant portion of the message
        byte[] msgPart = new byte[length];
        System.arraycopy(msg, offset, msgPart, 0, length);

        // L = 48 bytes for P-256 (ceil((256 + 128) / 8))
        // We need 2 * L = 96 bytes for two field elements
        byte[] uniformBytes = expandMessageXmd(msgPart, RFC9380_DST, 96);

        // hash_to_field: convert uniform bytes to two field elements u0 and u1
        byte[] u0Bytes = new byte[48];
        byte[] u1Bytes = new byte[48];
        System.arraycopy(uniformBytes, 0, u0Bytes, 0, 48);
        System.arraycopy(uniformBytes, 48, u1Bytes, 0, 48);

        BigInteger p = curve.getField().getCharacteristic();
        BigInteger u0 = new BigInteger(1, u0Bytes).mod(p);
        BigInteger u1 = new BigInteger(1, u1Bytes).mod(p);

        // Map u0 and u1 to curve points
        ECPoint P0 = mapToSswu(u0);
        ECPoint P1 = mapToSswu(u1);

        // Add the points: output = P0 + P1
        return P0.add(P1).normalize();
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    /**
     * Get intermediate values for debugging - returns expand_message_xmd output
     */
    public byte[] debugExpandMessageXmd(byte[] msg) throws NoSuchAlgorithmException {
        return expandMessageXmd(msg, RFC9380_DST, 96);
    }

    /**
     * Get verbose intermediate values for u1 calculation (128 bytes):
     *   - high_16_zeropadded (32 bytes)
     *   - low_32_after_mod (32 bytes)
     *   - high_times_pow256modp (32 bytes)
     *   - final_u1 (32 bytes)
     */
    public byte[] debugHashToFieldVerbose(byte[] msg) throws NoSuchAlgorithmException {
        // Expand to 96 bytes
        byte[] uniformBytes = expandMessageXmd(msg, RFC9380_DST, 96);

        // Get the 48 bytes for u1 (bytes 48-95)
        byte[] u1Bytes48 = new byte[48];
        System.arraycopy(uniformBytes, 48, u1Bytes48, 0, 48);

        // Split into high 16 and low 32
        byte[] high16 = new byte[16];
        byte[] low32 = new byte[32];
        System.arraycopy(u1Bytes48, 0, high16, 0, 16);
        System.arraycopy(u1Bytes48, 16, low32, 0, 32);

        BigInteger p = curve.getField().getCharacteristic();

        // Step 1: high_16_zeropadded (zero-pad to 32 bytes)
        byte[] high32 = new byte[32];
        System.arraycopy(high16, 0, high32, 16, 16);  // Copy high16 to last 16 bytes

        // Step 2: low_32_after_mod
        BigInteger lowValue = new BigInteger(1, low32).mod(p);
        byte[] lowValueBytes = lowValue.toByteArray();

        // Step 3: high * (2^256 mod p) mod p
        BigInteger highValue = new BigInteger(1, high16);
        BigInteger pow256modp = BigInteger.valueOf(2).modPow(BigInteger.valueOf(256), p);
        BigInteger highTimesPow = highValue.multiply(pow256modp).mod(p);
        byte[] highTimesPowBytes = highTimesPow.toByteArray();

        // Step 4: final u1 = (high * (2^256 mod p) + low) mod p
        BigInteger u1 = highTimesPow.add(lowValue).mod(p);
        byte[] u1Bytes = u1.toByteArray();

        // Prepare output: 128 bytes total
        byte[] result = new byte[128];

        // Copy high_16_zeropadded (32 bytes)
        System.arraycopy(high32, 0, result, 0, 32);

        // Copy low_32_after_mod (32 bytes), padding if needed
        int lowOffset = Math.max(0, lowValueBytes.length - 32);
        int lowDestOffset = 32 + Math.max(0, 32 - lowValueBytes.length);
        System.arraycopy(lowValueBytes, lowOffset, result, lowDestOffset, Math.min(32, lowValueBytes.length));

        // Copy high_times_pow256modp (32 bytes), padding if needed
        int highTimesPowOffset = Math.max(0, highTimesPowBytes.length - 32);
        int highTimesPowDestOffset = 64 + Math.max(0, 32 - highTimesPowBytes.length);
        System.arraycopy(highTimesPowBytes, highTimesPowOffset, result, highTimesPowDestOffset, Math.min(32, highTimesPowBytes.length));

        // Copy final_u1 (32 bytes), padding if needed
        int u1Offset = Math.max(0, u1Bytes.length - 32);
        int u1DestOffset = 96 + Math.max(0, 32 - u1Bytes.length);
        System.arraycopy(u1Bytes, u1Offset, result, u1DestOffset, Math.min(32, u1Bytes.length));

        return result;
    }

    /**
     * Get hash_to_field output for debugging - returns u0 (32 bytes) || u1 (32 bytes)
     */
    public byte[] debugHashToField(byte[] msg) throws NoSuchAlgorithmException {
        // Expand to 96 bytes
        byte[] uniformBytes = expandMessageXmd(msg, RFC9380_DST, 96);

        // Convert to field elements following RFC 9380
        // Each field element uses L=48 bytes
        byte[] u0Bytes48 = new byte[48];
        byte[] u1Bytes48 = new byte[48];
        System.arraycopy(uniformBytes, 0, u0Bytes48, 0, 48);
        System.arraycopy(uniformBytes, 48, u1Bytes48, 0, 48);

        BigInteger p = curve.getField().getCharacteristic();
        BigInteger u0 = new BigInteger(1, u0Bytes48).mod(p);
        BigInteger u1 = new BigInteger(1, u1Bytes48).mod(p);

        // Convert to 32-byte arrays
        byte[] u0Bytes = u0.toByteArray();
        byte[] u1Bytes = u1.toByteArray();

        // Prepare output: u0 (32 bytes) || u1 (32 bytes)
        byte[] result = new byte[64];

        // Copy u0, padding with zeros if needed (BigInteger may add sign byte)
        int u0Offset = Math.max(0, u0Bytes.length - 32);
        int u0DestOffset = Math.max(0, 32 - u0Bytes.length);
        System.arraycopy(u0Bytes, u0Offset, result, u0DestOffset, Math.min(32, u0Bytes.length));

        // Copy u1, padding with zeros if needed (BigInteger may add sign byte)
        int u1Offset = Math.max(0, u1Bytes.length - 32);
        int u1DestOffset = 32 + Math.max(0, 32 - u1Bytes.length);
        System.arraycopy(u1Bytes, u1Offset, result, u1DestOffset, Math.min(32, u1Bytes.length));

        return result;
    }

    /**
     * Test RFC 9380 test vectors for P256_XMD:SHA-256_SSWU_RO_
     * Test vectors from: https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve/blob/main/poc/vectors/P256_XMD:SHA-256_SSWU_RO_.json
     */
    public void testRfc9380Vectors() throws NoSuchAlgorithmException {
        // Test vector 1: empty message
        testVector(
            "",
            "0x2c15230b26dbc6fc9a37051158c95b79656e17a1a920b11394ca91c44247d3e4",
            "0x8a7a74985cc5c776cdfe4b1f19884970453912e9d31528c060be9ab5c43e8415",
            1
        );

        // Test vector 2: "abc"
        testVector(
            "abc",
            "0x0bb8b87485551aa43ed54f009230450b492fead5f1cc91658775dac4a3388a0f",
            "0x5c41b3d0731a27a7b14bc0bf0ccded2d8751f83493404c84a88e71ffd424212e",
            2
        );

        // Test vector 3: "abcdef0123456789"
        testVector(
            "abcdef0123456789",
            "0x65038ac8f2b1def042a5df0b33b1f4eca6bff7cb0f9c6c1526811864e544ed80",
            "0xcad44d40a656e7aff4002a8de287abc8ae0482b5ae825822bb870d6df9b56ca3",
            3
        );

        // Test vector 4: "q128_" prefix indicates 128 q's follow (not total)
        // From RFC: msg = q128_qqqq... (where there are 128 q's after the underscore)
        StringBuilder sb128 = new StringBuilder("q128_");
        for (int i = 0; i < 128; i++) {
            sb128.append('q');
        }
        testVector(
            sb128.toString(),
            "0x4be61ee205094282ba8a2042bcb48d88dfbb609301c49aa8b078533dc65a0b5d",
            "0x98f8df449a072c4721d241a3b1236d3caccba603f916ca680f4539d2bfb3c29e",
            4
        );

        // Test vector 5: "a512_" prefix indicates 512 a's follow (not total)
        // From RFC: msg = a512_aaaa... (where there are 512 a's after the underscore)
        StringBuilder sb512 = new StringBuilder("a512_");
        for (int i = 0; i < 512; i++) {
            sb512.append('a');
        }
        testVector(
            sb512.toString(),
            "0x457ae2981f70ca85d8e24c308b14db22f3e3862c5ea0f652ca38b5e49cd64bc5",
            "0xecb9f0eadc9aeed232dabc53235368c1394c78de05dd96893eefa62b0f4757dc",
            5
        );
    }

    private void testVector(String message, String expectedX, String expectedY, int vectorNum) throws NoSuchAlgorithmException {
        byte[] msg = message.getBytes();
        ECPoint result = hashToCurveRfc9380(msg, 0, msg.length);

        // Parse expected coordinates (remove "0x" prefix)
        BigInteger expX = new BigInteger(expectedX.substring(2), 16);
        BigInteger expY = new BigInteger(expectedY.substring(2), 16);

        // Get actual coordinates
        BigInteger actX = result.getAffineXCoord().toBigInteger();
        BigInteger actY = result.getAffineYCoord().toBigInteger();

        // Use JUnit assertions with informative messages
        String messagePrefix = message.substring(0, Math.min(20, message.length())) +
                              (message.length() > 20 ? "..." : "");
        Assert.assertEquals(
            "Test Vector " + vectorNum + " (" + messagePrefix + "): X coordinate mismatch",
            expX,
            actX
        );
        Assert.assertEquals(
            "Test Vector " + vectorNum + " (" + messagePrefix + "): Y coordinate mismatch",
            expY,
            actY
        );
    }

    /**
     * Get only P0 from hash-to-curve (for debugging)
     */
    public ECPoint getP0Only(byte[] msg, int offset, int length) throws NoSuchAlgorithmException {
        byte[] uniformBytes = expandMessageXmd(msg, RFC9380_DST, 96);

        byte[] u0Bytes = new byte[48];
        System.arraycopy(uniformBytes, 0, u0Bytes, 0, 48);

        BigInteger p = curve.getField().getCharacteristic();
        BigInteger u0 = new BigInteger(1, u0Bytes).mod(p);

        return mapToSswu(u0);
    }

    /**
     * Get only P1 from hash-to-curve (for debugging)
     */
    public ECPoint getP1Only(byte[] msg, int offset, int length) throws NoSuchAlgorithmException {
        byte[] uniformBytes = expandMessageXmd(msg, RFC9380_DST, 96);

        byte[] u1Bytes = new byte[48];
        System.arraycopy(uniformBytes, 48, u1Bytes, 0, 48);

        BigInteger p = curve.getField().getCharacteristic();
        BigInteger u1 = new BigInteger(1, u1Bytes).mod(p);

        return mapToSswu(u1);
    }
}
