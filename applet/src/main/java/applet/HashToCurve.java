package applet;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.MessageDigest;
import applet.jcmathlib.*;

// Source: https://github.com/crocs-muni/JCMint/blob/main/applet/src/main/java/jcmint/HashToCurve.java
public class HashToCurve {
    public static final byte[] H2C_DOMAIN_SEPARATOR = {
        (byte) 0x53, (byte) 0x65, (byte) 0x63, (byte) 0x70,
        (byte) 0x32, (byte) 0x35, (byte) 0x36, (byte) 0x6b,
        (byte) 0x31, (byte) 0x5f, (byte) 0x48, (byte) 0x61,
        (byte) 0x73, (byte) 0x68, (byte) 0x54, (byte) 0x6f,
        (byte) 0x43, (byte) 0x75, (byte) 0x72, (byte) 0x76,
        (byte) 0x65, (byte) 0x5f, (byte) 0x43, (byte) 0x61,
        (byte) 0x73, (byte) 0x68, (byte) 0x75, (byte) 0x5f
    };

    // RFC 9380 P256_XMD:SHA-256_SSWU_RO_ DST
    public static final byte[] RFC9380_DST = {
        (byte) 0x51, (byte) 0x55, (byte) 0x55, (byte) 0x58, (byte) 0x2d, (byte) 0x56, (byte) 0x30, (byte) 0x31,
        (byte) 0x2d, (byte) 0x43, (byte) 0x53, (byte) 0x30, (byte) 0x32, (byte) 0x2d, (byte) 0x77, (byte) 0x69,
        (byte) 0x74, (byte) 0x68, (byte) 0x2d, (byte) 0x50, (byte) 0x32, (byte) 0x35, (byte) 0x36, (byte) 0x5f,
        (byte) 0x58, (byte) 0x4d, (byte) 0x44, (byte) 0x3a, (byte) 0x53, (byte) 0x48, (byte) 0x41, (byte) 0x2d,
        (byte) 0x32, (byte) 0x35, (byte) 0x36, (byte) 0x5f, (byte) 0x53, (byte) 0x53, (byte) 0x57, (byte) 0x55,
        (byte) 0x5f, (byte) 0x52, (byte) 0x4f, (byte) 0x5f
    };

    private final MessageDigest md = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
    private final byte[] prefixBuffer = JCSystem.makeTransientByteArray((short) 36, JCSystem.CLEAR_ON_RESET);
    private final byte[] ramArray = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_RESET);

    // RFC 9380 working buffers
    private final byte[] expandBuffer = JCSystem.makeTransientByteArray((short) 96, JCSystem.CLEAR_ON_RESET);
    private final byte[] b0Buffer = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_RESET);
    private final byte[] dstPrimeBuffer = new byte[45];
    private final byte[] tmpBuffer = JCSystem.makeTransientByteArray((short) 64, JCSystem.CLEAR_ON_RESET);

    // RFC 9380 BigNats - reuse existing transient BigNats to save memory
    // Reuse from DiscreteLogEquality (TRANSIENT_RESET)
    private jcmathlib.BigNat rfc_u0;      // -> DiscreteLogEquality.r (32 bytes)
    private jcmathlib.BigNat rfc_u1;      // -> DiscreteLogEquality.ch (32 bytes)
    private jcmathlib.BigNat rfc_tmp;     // -> DiscreteLogEquality.tmpNum (48 bytes)
    private jcmathlib.BigNat rfc_Z;       // -> DiscreteLogEquality.curveOrder (32 bytes)
    private jcmathlib.BigNat rfc_tv1;     // -> DiscreteLogEquality.aBN (32 bytes)
    private jcmathlib.BigNat rfc_tv2;     // -> DiscreteLogEquality.bBN (32 bytes)

    // Reuse from DistributedKeyGen (TRANSIENT_RESET)
    private jcmathlib.BigNat rfc_x1;      // -> DistributedKeyGen.ch (32 bytes)
    private jcmathlib.BigNat rfc_x2;      // -> DistributedKeyGen.tmpNum (32 bytes)

    // Reuse from Musig2 (TRANSIENT_DESELECT)
    private jcmathlib.BigNat rfc_gx1;     // -> Musig2.tmpBigNat (32 bytes)
    private jcmathlib.BigNat rfc_gx2;     // -> Musig2.coefB (32 bytes)
    private jcmathlib.BigNat rfc_y;       // -> Musig2.challangeE (32 bytes)

    // Allocated locally (32 bytes total)
    private jcmathlib.BigNat rfc_work;    // General work variable

    // Precomputed constants (192 bytes total)
    private jcmathlib.BigNat precomp_inv3;   // 1/3 mod p (for x1 calculation)
    private jcmathlib.BigNat precomp_B_div_3; // B/3 mod p (for x1 calculation)
    private jcmathlib.BigNat precomp_Z;      // Z = -10 mod p (for SSWU map)
    private jcmathlib.BigNat precomp_B_div_ZA; // B/(Z*A) mod p (for tv2==0 edge case)
    private jcmathlib.BigNat precomp_one;    // Constant 1 (to avoid setValue calls)
    private jcmathlib.BigNat precomp_three;  // Constant 3 (for curve equation optimization)

    // Temporary ECPoint for P1 in hashToCurveRfc9380 (reused to avoid allocation in hot path)
    private jcmathlib.ECPoint rfc_P1;

    public HashToCurve() {
        // Reuse DiscreteLogEquality's transient BigNats (208 bytes saved)
        rfc_tmp = DiscreteLogEquality.tmpNum;      // 48 bytes
        rfc_u0 = DiscreteLogEquality.r;            // 32 bytes
        rfc_u1 = DiscreteLogEquality.ch;           // 32 bytes
        rfc_Z = DiscreteLogEquality.curveOrder;    // 32 bytes
        rfc_tv1 = DiscreteLogEquality.aBN;         // 32 bytes
        rfc_tv2 = DiscreteLogEquality.bBN;         // 32 bytes

        // Reuse DistributedKeyGen's transient BigNats (64 bytes saved)
        rfc_x1 = DistributedKeyGen.ch;             // 32 bytes
        rfc_x2 = DistributedKeyGen.tmpNum;         // 32 bytes

        // Reuse Musig2's transient BigNats (96 bytes saved)
        rfc_gx1 = IndistinguishabilityApplet.musig2.tmpBigNat;      // 32 bytes
        rfc_gx2 = IndistinguishabilityApplet.musig2.coefB;          // 32 bytes
        rfc_y = IndistinguishabilityApplet.musig2.challangeE;       // 32 bytes

        // Allocate work variable and temporary point
        // Total memory saved: 368 bytes of TRANSIENT memory
        rfc_work = new jcmathlib.BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, IndistinguishabilityApplet.rm);
        rfc_P1 = new jcmathlib.ECPoint(IndistinguishabilityApplet.curve);

        // Precompute constants for SSWU optimization
        precomp_inv3 = new jcmathlib.BigNat((short) 32, JCSystem.MEMORY_TYPE_PERSISTENT, IndistinguishabilityApplet.rm);
        precomp_B_div_3 = new jcmathlib.BigNat((short) 32, JCSystem.MEMORY_TYPE_PERSISTENT, IndistinguishabilityApplet.rm);
        precomp_Z = new jcmathlib.BigNat((short) 32, JCSystem.MEMORY_TYPE_PERSISTENT, IndistinguishabilityApplet.rm);
        precomp_B_div_ZA = new jcmathlib.BigNat((short) 32, JCSystem.MEMORY_TYPE_PERSISTENT, IndistinguishabilityApplet.rm);
        precomp_one = new jcmathlib.BigNat((short) 32, JCSystem.MEMORY_TYPE_PERSISTENT, IndistinguishabilityApplet.rm);
        precomp_three = new jcmathlib.BigNat((short) 32, JCSystem.MEMORY_TYPE_PERSISTENT, IndistinguishabilityApplet.rm);

        // Compute 1/3 mod p
        precomp_inv3.setValue((byte) 3);
        precomp_inv3.modInv(IndistinguishabilityApplet.curve.pBN);

        // Compute B/3 mod p
        precomp_B_div_3.copy(IndistinguishabilityApplet.curve.bBN);
        precomp_B_div_3.modMult(precomp_inv3, IndistinguishabilityApplet.curve.pBN);

        // Compute Z = -10 mod p = p - 10
        precomp_Z.copy(IndistinguishabilityApplet.curve.pBN);
        rfc_work.setValue((byte) 10);
        precomp_Z.modSub(rfc_work, IndistinguishabilityApplet.curve.pBN);

        // Compute B/(Z*A) mod p for tv2==0 edge case
        // precomp_B_div_ZA = B / (Z * A)
        precomp_B_div_ZA.copy(precomp_Z);
        precomp_B_div_ZA.modMult(IndistinguishabilityApplet.curve.aBN, IndistinguishabilityApplet.curve.pBN); // Z * A
        precomp_B_div_ZA.modInv(IndistinguishabilityApplet.curve.pBN); // 1 / (Z * A)
        rfc_work.copy(IndistinguishabilityApplet.curve.bBN);
        rfc_work.modMult(precomp_B_div_ZA, IndistinguishabilityApplet.curve.pBN); // B * (1 / (Z * A))
        precomp_B_div_ZA.copy(rfc_work);

        // Compute constant 1
        precomp_one.setValue((byte) 1);

        // Compute constant 3 (for curve equation optimization where A=-3)
        precomp_three.setValue((byte) 3);

        // Precompute DST_prime = DST || I2OSP(len(DST), 1)
        Util.arrayCopyNonAtomic(RFC9380_DST, (short) 0, dstPrimeBuffer, (short) 0, (short) RFC9380_DST.length);
        dstPrimeBuffer[RFC9380_DST.length] = (byte) RFC9380_DST.length;
    }

    public boolean hash(byte[] data, short offset, short length, ECPoint output) {
        Util.arrayFillNonAtomic(prefixBuffer, (short) 32, (short) 4, (byte) 0);
        md.reset();
        md.update(H2C_DOMAIN_SEPARATOR, (short) 0, (short) H2C_DOMAIN_SEPARATOR.length);
        md.doFinal(data, offset, length, prefixBuffer, (short) 0);

        boolean validPoint = false;

        for (short counter = 0; counter < (short) 256; ++counter) { // TODO consider increasing max number of iters
            md.reset();
            prefixBuffer[32] = (byte) (counter & 0xff);
            md.doFinal(prefixBuffer, (short) 0, (short) prefixBuffer.length, ramArray, (short) 0);
            if (output.fromX(ramArray, (short) 0, (short) 32)) {
                validPoint = true;
                break;
            }
        }

        if (!output.isYEven()) {
            output.negate();
        }

        return validPoint;
    }

    /**
     * RFC 9380: expand_message_xmd for SHA-256
     * Expands a message to a uniform byte string of 96 bytes (for P-256)
     * Result is stored in expandBuffer
     */
    private void expandMessageXmd(byte[] msg, short msgOffset, short msgLength) {
        // DST_prime is precomputed in constructor

        // Compute b_0 = H(Z_pad || msg || I2OSP(len_in_bytes, 2) || I2OSP(0, 1) || DST_prime)
        // Z_pad is 64 zero bytes (SHA-256 block size)
        md.reset();
        // Add 64 zero bytes
        Util.arrayFillNonAtomic(tmpBuffer, (short) 0, (short) 64, (byte) 0);
        md.update(tmpBuffer, (short) 0, (short) 64);
        // Add message
        md.update(msg, msgOffset, msgLength);
        // Add I2OSP(96, 2) - length in bytes
        // tmpBuffer[0] already 0 from arrayFill above
        tmpBuffer[1] = (byte) 0x60; // 96 in hex
        md.update(tmpBuffer, (short) 0, (short) 2);
        // Add I2OSP(0, 1)
        // tmpBuffer[0] already 0 from arrayFill above
        md.update(tmpBuffer, (short) 0, (short) 1);
        // Add DST_prime
        md.update(dstPrimeBuffer, (short) 0, (short) (RFC9380_DST.length + 1));
        md.doFinal(tmpBuffer, (short) 0, (short) 0, b0Buffer, (short) 0);

        // Compute b_1 = H(b_0 || I2OSP(1, 1) || DST_prime)
        md.reset();
        md.update(b0Buffer, (short) 0, (short) 32);
        tmpBuffer[0] = (byte) 0x01;
        md.update(tmpBuffer, (short) 0, (short) 1);
        md.update(dstPrimeBuffer, (short) 0, (short) (RFC9380_DST.length + 1));
        md.doFinal(tmpBuffer, (short) 0, (short) 0, expandBuffer, (short) 0);

        // Compute b_2 = H(b_0 XOR b_1 || I2OSP(2, 1) || DST_prime)
        // XOR b_0 with b_1 into tmpBuffer (8-way unrolled)
        for (short i = 0; i < 32; i += 8) {
            tmpBuffer[i] = (byte) (b0Buffer[i] ^ expandBuffer[i]);
            tmpBuffer[(short)(i+1)] = (byte) (b0Buffer[(short)(i+1)] ^ expandBuffer[(short)(i+1)]);
            tmpBuffer[(short)(i+2)] = (byte) (b0Buffer[(short)(i+2)] ^ expandBuffer[(short)(i+2)]);
            tmpBuffer[(short)(i+3)] = (byte) (b0Buffer[(short)(i+3)] ^ expandBuffer[(short)(i+3)]);
            tmpBuffer[(short)(i+4)] = (byte) (b0Buffer[(short)(i+4)] ^ expandBuffer[(short)(i+4)]);
            tmpBuffer[(short)(i+5)] = (byte) (b0Buffer[(short)(i+5)] ^ expandBuffer[(short)(i+5)]);
            tmpBuffer[(short)(i+6)] = (byte) (b0Buffer[(short)(i+6)] ^ expandBuffer[(short)(i+6)]);
            tmpBuffer[(short)(i+7)] = (byte) (b0Buffer[(short)(i+7)] ^ expandBuffer[(short)(i+7)]);
        }
        md.reset();
        md.update(tmpBuffer, (short) 0, (short) 32);
        tmpBuffer[0] = (byte) 0x02;
        md.update(tmpBuffer, (short) 0, (short) 1);
        md.update(dstPrimeBuffer, (short) 0, (short) (RFC9380_DST.length + 1));
        md.doFinal(tmpBuffer, (short) 0, (short) 0, expandBuffer, (short) 32);

        // Compute b_3 = H(b_0 XOR b_2 || I2OSP(3, 1) || DST_prime)
        // XOR b_0 with b_2 into tmpBuffer (8-way unrolled)
        for (short i = 0; i < 32; i += 8) {
            tmpBuffer[i] = (byte) (b0Buffer[i] ^ expandBuffer[(short)(32+i)]);
            tmpBuffer[(short)(i+1)] = (byte) (b0Buffer[(short)(i+1)] ^ expandBuffer[(short)(32+i+1)]);
            tmpBuffer[(short)(i+2)] = (byte) (b0Buffer[(short)(i+2)] ^ expandBuffer[(short)(32+i+2)]);
            tmpBuffer[(short)(i+3)] = (byte) (b0Buffer[(short)(i+3)] ^ expandBuffer[(short)(32+i+3)]);
            tmpBuffer[(short)(i+4)] = (byte) (b0Buffer[(short)(i+4)] ^ expandBuffer[(short)(32+i+4)]);
            tmpBuffer[(short)(i+5)] = (byte) (b0Buffer[(short)(i+5)] ^ expandBuffer[(short)(32+i+5)]);
            tmpBuffer[(short)(i+6)] = (byte) (b0Buffer[(short)(i+6)] ^ expandBuffer[(short)(32+i+6)]);
            tmpBuffer[(short)(i+7)] = (byte) (b0Buffer[(short)(i+7)] ^ expandBuffer[(short)(32+i+7)]);
        }
        md.reset();
        md.update(tmpBuffer, (short) 0, (short) 32);
        tmpBuffer[0] = (byte) 0x03;
        md.update(tmpBuffer, (short) 0, (short) 1);
        md.update(dstPrimeBuffer, (short) 0, (short) (RFC9380_DST.length + 1));
        md.doFinal(tmpBuffer, (short) 0, (short) 0, expandBuffer, (short) 64);

        // expandBuffer now contains 96 bytes of uniform random data
    }

    /**
     * RFC 9380: hash_to_curve for P-256 using Simplified SWU
     * This method implements the full RFC 9380 hash-to-curve algorithm
     */
    public boolean hashToCurveRfc9380(byte[] data, short offset, short length, jcmathlib.ECPoint output) {
        // Get curve from global IndistinguishabilityApplet
        jcmathlib.ECCurve curve = IndistinguishabilityApplet.curve;

        // Step 1: Expand message to 96 bytes
        expandMessageXmd(data, offset, length);

        // Step 2 & 3: Load u0 and map to first curve point
        // Load u0 into rfc_tmp (48 bytes), reduce mod p, then copy to 32-byte BigNat
        rfc_tmp.fromByteArray(expandBuffer, (short) 0, (short) 48);
        rfc_tmp.mod(curve.pBN);
        rfc_u0.copy(rfc_tmp);  // Copy to 32-byte BigNat for faster operations
        mapToSswu(rfc_u0, output);

        // Step 4: Load u1 and map to second curve point
        rfc_tmp.fromByteArray(expandBuffer, (short) 48, (short) 48);
        rfc_tmp.mod(curve.pBN);
        rfc_u1.copy(rfc_tmp);  // Copy to 32-byte BigNat for faster operations
        mapToSswu(rfc_u1, rfc_P1);

        // Step 5: Add the points: output = P0 + P1
        output.add(rfc_P1);

        return true;
    }

    /**
     * Debug method: Map only u0 to output (for testing P0)
     */
    public boolean hashToCurveRfc9380_P0Only(byte[] data, short offset, short length, jcmathlib.ECPoint output) {
        jcmathlib.ECCurve curve = IndistinguishabilityApplet.curve;
        expandMessageXmd(data, offset, length);

        // Load u0 via rfc_tmp
        rfc_tmp.fromByteArray(expandBuffer, (short) 0, (short) 48);
        rfc_tmp.mod(curve.pBN);
        rfc_u0.copy(rfc_tmp);

        mapToSswu(rfc_u0, output);
        return true;
    }

    /**
     * Debug method: Get u0 value after expand_message_xmd (for debugging)
     * Returns the 32-byte u0 value (first 48 bytes of uniform output, reduced mod p)
     */
    public short getU0Value(byte[] data, short offset, short length, byte[] output, short outOffset) {
        jcmathlib.ECCurve curve = IndistinguishabilityApplet.curve;
        expandMessageXmd(data, offset, length);

        // Load first 48 bytes and reduce mod p
        rfc_tmp.fromByteArray(expandBuffer, (short) 0, (short) 48);
        rfc_tmp.mod(curve.pBN);

        // Copy to tmpBuffer
        short len = rfc_tmp.copyToByteArray(tmpBuffer, (short) 0);

        // Find first non-zero byte to strip leading zeros
        short start = 0;
        while (start < len && tmpBuffer[start] == 0) {
            start++;
        }

        // Calculate actual data length (without leading zeros)
        short dataLen = (short) (len - start);

        // Pad to 32 bytes if needed
        if (dataLen > 32) {
            // Value too large - this shouldn't happen after mod p for P-256
            dataLen = 32;
            start = (short) (len - 32);
        }

        // Write with leading zeros to make it exactly 32 bytes
        short padLen = (short) (32 - dataLen);
        Util.arrayFillNonAtomic(output, outOffset, padLen, (byte) 0);
        Util.arrayCopyNonAtomic(tmpBuffer, start, output, (short) (outOffset + padLen), dataLen);

        return (short) 32;
    }

    /**
     * Debug method: Get x1 and gx1 values from SSWU algorithm
     * Returns: x1 (32 bytes) || gx1 (32 bytes) = 64 bytes total
     */
    public short getX1Gx1Values(byte[] data, short offset, short length, byte[] output, short outOffset) {
        jcmathlib.ECCurve curve = IndistinguishabilityApplet.curve;
        expandMessageXmd(data, offset, length);

        // Get u0 - load into rfc_tmp first, then copy to rfc_u0
        rfc_tmp.fromByteArray(expandBuffer, (short) 0, (short) 48);
        rfc_tmp.mod(curve.pBN);
        rfc_u0.copy(rfc_tmp);

        // Now run the beginning of mapToSswu to get x1 and gx1
        jcmathlib.BigNat u = rfc_u0;
        jcmathlib.BigNat Z = rfc_Z;
        jcmathlib.BigNat tv1 = rfc_tv1;
        jcmathlib.BigNat tv2 = rfc_tv2;
        jcmathlib.BigNat x1 = rfc_x1;
        jcmathlib.BigNat gx1 = rfc_gx1;
        jcmathlib.BigNat tmp = rfc_work;

        // Z = -10 mod p (precomputed)
        Z.copy(precomp_Z);

        // tv1 = u^2
        tv1.copy(u);
        tv1.modSq(curve.pBN);

        // tv1 = Z * u^2
        tv1.modMult(Z, curve.pBN);

        // tv2 = tv1^2
        tv2.copy(tv1);
        tv2.modSq(curve.pBN);

        // tv2 = tv2 + tv1
        tv2.modAdd(tv1, curve.pBN);

        // tv2 = inv0(tv2)
        boolean tv2IsZero = tv2.isZero();
        if (!tv2IsZero) {
            tv2.modInv(curve.pBN);
        }
        // else: tv2 is already zero, no need to call zero() again

        // x1 = (-B / A) * (1 + tv2) - using precomputed B/3
        x1.copy(precomp_B_div_3);  // x1 = B/3

        tmp.copy(precomp_one);
        tmp.modAdd(tv2, curve.pBN);   // tmp = 1 + tv2
        x1.modMult(tmp, curve.pBN);   // x1 = (B/3) * (1 + tv2)

        // gx1 = x1^3 + A*x1 + B
        // For P-256 where A=-3, optimize to: x1(x1^2 - 3) + B
        tmp.copy(x1);
        tmp.modSq(curve.pBN);      // x1^2
        tmp.modSub(precomp_three, curve.pBN);  // x1^2 - 3
        gx1.copy(x1);
        gx1.modMult(tmp, curve.pBN); // x1 * (x1^2 - 3)
        gx1.modAdd(curve.bBN, curve.pBN); // + B

        // Format output: x1 (32 bytes) || gx1 (32 bytes)
        short x1Len = x1.copyToByteArray(tmpBuffer, (short) 0);
        short x1Start = 0;
        while (x1Start < x1Len && tmpBuffer[x1Start] == 0) {
            x1Start++;
        }
        short x1DataLen = (short) (x1Len - x1Start);
        if (x1DataLen > 32) {
            x1DataLen = 32;
            x1Start = (short) (x1Len - 32);
        }
        short x1PadLen = (short) (32 - x1DataLen);
        Util.arrayFillNonAtomic(output, outOffset, x1PadLen, (byte) 0);
        Util.arrayCopyNonAtomic(tmpBuffer, x1Start, output, (short) (outOffset + x1PadLen), x1DataLen);

        short gx1Len = gx1.copyToByteArray(tmpBuffer, (short) 0);
        short gx1Start = 0;
        while (gx1Start < gx1Len && tmpBuffer[gx1Start] == 0) {
            gx1Start++;
        }
        short gx1DataLen = (short) (gx1Len - gx1Start);
        if (gx1DataLen > 32) {
            gx1DataLen = 32;
            gx1Start = (short) (gx1Len - 32);
        }
        short gx1PadLen = (short) (32 - gx1DataLen);
        Util.arrayFillNonAtomic(output, (short) (outOffset + 32), gx1PadLen, (byte) 0);
        Util.arrayCopyNonAtomic(tmpBuffer, gx1Start, output, (short) (outOffset + 32 + gx1PadLen), gx1DataLen);

        return (short) 64;
    }

    /**
     * Debug method: Get tv1 and tv2 values (after inversion) from SSWU algorithm
     * Returns: tv1 (32 bytes) || tv2_inv (32 bytes) = 64 bytes total
     */
    public short getTv1Tv2Values(byte[] data, short offset, short length, byte[] output, short outOffset) {
        jcmathlib.ECCurve curve = IndistinguishabilityApplet.curve;
        expandMessageXmd(data, offset, length);

        // Get u0 - load into rfc_tmp first, then copy to rfc_u0
        rfc_tmp.fromByteArray(expandBuffer, (short) 0, (short) 48);
        rfc_tmp.mod(curve.pBN);
        rfc_u0.copy(rfc_tmp);

        jcmathlib.BigNat u = rfc_u0;
        jcmathlib.BigNat Z = rfc_Z;
        jcmathlib.BigNat tv1 = rfc_tv1;
        jcmathlib.BigNat tv2 = rfc_tv2;
        jcmathlib.BigNat tmp = rfc_work;

        // Z = -10 mod p (precomputed)
        Z.copy(precomp_Z);

        // tv1 = u^2
        tv1.copy(u);
        tv1.modSq(curve.pBN);

        // tv1 = Z * u^2
        tv1.modMult(Z, curve.pBN);

        // tv2 = tv1^2
        tv2.copy(tv1);
        tv2.modSq(curve.pBN);

        // tv2 = tv2 + tv1
        tv2.modAdd(tv1, curve.pBN);

        // Save tv2 before inversion
        jcmathlib.BigNat tv2_before_inv = rfc_x1;  // Borrow x1 temporarily
        tv2_before_inv.copy(tv2);

        // tv2 = inv0(tv2)
        boolean tv2IsZero = tv2.isZero();
        if (!tv2IsZero) {
            tv2.modInv(curve.pBN);
        }
        // else: tv2 is already zero, no need to call zero() again

        // Format output: tv1 (32 bytes) || tv2_inv (32 bytes)
        // Return tv1 and tv2 AFTER inversion
        short tv1Len = tv1.copyToByteArray(tmpBuffer, (short) 0);
        short tv1Start = 0;
        while (tv1Start < tv1Len && tmpBuffer[tv1Start] == 0) {
            tv1Start++;
        }
        short tv1DataLen = (short) (tv1Len - tv1Start);
        if (tv1DataLen > 32) {
            tv1DataLen = 32;
            tv1Start = (short) (tv1Len - 32);
        }
        short tv1PadLen = (short) (32 - tv1DataLen);
        Util.arrayFillNonAtomic(output, outOffset, tv1PadLen, (byte) 0);
        Util.arrayCopyNonAtomic(tmpBuffer, tv1Start, output, (short) (outOffset + tv1PadLen), tv1DataLen);

        short tv2Len = tv2.copyToByteArray(tmpBuffer, (short) 0);
        short tv2Start = 0;
        while (tv2Start < tv2Len && tmpBuffer[tv2Start] == 0) {
            tv2Start++;
        }
        short tv2DataLen = (short) (tv2Len - tv2Start);
        if (tv2DataLen > 32) {
            tv2DataLen = 32;
            tv2Start = (short) (tv2Len - 32);
        }
        short tv2PadLen = (short) (32 - tv2DataLen);
        Util.arrayFillNonAtomic(output, (short) (outOffset + 32), tv2PadLen, (byte) 0);
        Util.arrayCopyNonAtomic(tmpBuffer, tv2Start, output, (short) (outOffset + 32 + tv2PadLen), tv2DataLen);

        return (short) 64;
    }

    /**
     * Debug method: Get Z value (Z = -10 mod p)
     * Returns: Z (32 bytes)
     */
    public short getZValue(byte[] output, short outOffset) {
        // Return precomputed Z value
        jcmathlib.BigNat Z = rfc_Z;
        Z.copy(precomp_Z);

        // Format output
        short zLen = Z.copyToByteArray(tmpBuffer, (short) 0);
        short zStart = 0;
        while (zStart < zLen && tmpBuffer[zStart] == 0) {
            zStart++;
        }
        short zDataLen = (short) (zLen - zStart);
        if (zDataLen > 32) {
            zDataLen = 32;
            zStart = (short) (zLen - 32);
        }
        short zPadLen = (short) (32 - zDataLen);
        Util.arrayFillNonAtomic(output, outOffset, zPadLen, (byte) 0);
        Util.arrayCopyNonAtomic(tmpBuffer, zStart, output, (short) (outOffset + zPadLen), zDataLen);

        return (short) 32;
    }

    /**
     * Debug method: Get u^2 value (for debugging)
     * Returns the 32-byte u^2 value
     */
    public short getU2Value(byte[] data, short offset, short length, byte[] output, short outOffset) {
        jcmathlib.ECCurve curve = IndistinguishabilityApplet.curve;
        expandMessageXmd(data, offset, length);

        // Load first 48 bytes and reduce mod p to get u0
        rfc_tmp.fromByteArray(expandBuffer, (short) 0, (short) 48);
        rfc_tmp.mod(curve.pBN);

        // Copy to rfc_u0 and compute u^2
        rfc_u0.copy(rfc_tmp);
        rfc_u0.modMult(rfc_tmp, curve.pBN);

        // Copy result to tmpBuffer
        short len = rfc_u0.copyToByteArray(tmpBuffer, (short) 0);

        // Find first non-zero byte to strip leading zeros
        short start = 0;
        while (start < len && tmpBuffer[start] == 0) {
            start++;
        }

        // Calculate actual data length (without leading zeros)
        short dataLen = (short) (len - start);

        // Pad to 32 bytes if needed
        if (dataLen > 32) {
            dataLen = 32;
            start = (short) (len - 32);
        }

        // Write with leading zeros to make it exactly 32 bytes
        short padLen = (short) (32 - dataLen);
        Util.arrayFillNonAtomic(output, outOffset, padLen, (byte) 0);
        Util.arrayCopyNonAtomic(tmpBuffer, start, output, (short) (outOffset + padLen), dataLen);

        return (short) 32;
    }

    /**
     * Debug method: Map only u1 to output (for testing P1)
     */
    public boolean hashToCurveRfc9380_P1Only(byte[] data, short offset, short length, jcmathlib.ECPoint output) {
        jcmathlib.ECCurve curve = IndistinguishabilityApplet.curve;
        expandMessageXmd(data, offset, length);

        // Load u1 via rfc_tmp
        rfc_tmp.fromByteArray(expandBuffer, (short) 48, (short) 48);
        rfc_tmp.mod(curve.pBN);
        rfc_u1.copy(rfc_tmp);

        mapToSswu(rfc_u1, output);
        return true;
    }

    /**
     * RFC 9380: Simplified SWU map for P-256
     * Maps a field element u to a point on the curve
     */
    private void mapToSswu(jcmathlib.BigNat u, jcmathlib.ECPoint output) {
        jcmathlib.ECCurve curve = IndistinguishabilityApplet.curve;

        // Use dedicated RFC9380 BigNats - no conflicts with ResourceManager or other operations
        // All of these are 32 bytes, sized for P-256 field elements
        jcmathlib.BigNat tv1 = rfc_tv1;
        jcmathlib.BigNat tv2 = rfc_tv2;
        jcmathlib.BigNat x1 = rfc_x1;
        jcmathlib.BigNat gx1 = rfc_gx1;
        jcmathlib.BigNat gx2 = rfc_gx2;
        jcmathlib.BigNat y = rfc_y;
        jcmathlib.BigNat tmp = rfc_work;
        // Note: tv1 will be reused as x2 after line 616 (rename for clarity)
        jcmathlib.BigNat x2;

        // Save u's oddness (u is already in a dedicated BigNat, so it's safe)
        boolean sgn0_u = u.isOdd();

        // tv1 = u^2
        tv1.copy(u);
        tv1.modSq(curve.pBN);

        // tv1 = Z * u^2 (using precomputed Z directly)
        tv1.modMult(precomp_Z, curve.pBN);

        // tv2 = tv1^2
        tv2.copy(tv1);
        tv2.modSq(curve.pBN);

        // tv2 = tv2 + tv1
        tv2.modAdd(tv1, curve.pBN);

        // After this point, tv1 (which contains Z * u^2) will be reused as x2
        x2 = tv1;

        // tv2 = inv0(tv2) - compute modular inverse if tv2 != 0, else 0
        boolean tv2IsZero = tv2.isZero();
        if (!tv2IsZero) {
            tv2.modInv(curve.pBN);
        }
        // else: tv2 is already zero, no need to call zero() again

        // x1 = (-B / A) * (1 + tv2)
        // For P-256: A = -3, B = curve.b
        // -B/A = B/3 (precomputed)
        x1.copy(precomp_B_div_3);  // x1 = B/3

        tmp.copy(precomp_one);
        tmp.modAdd(tv2, curve.pBN);   // tmp = 1 + tv2
        x1.modMult(tmp, curve.pBN);   // x1 = (B/3) * (1 + tv2)

        // If tv2 == 0, set x1 = B / (Z * A) (precomputed)
        if (tv2IsZero) {
            x1.copy(precomp_B_div_ZA);
        }

        // gx1 = x1^3 + A*x1 + B
        // For P-256 where A=-3, optimize to: x1(x1^2 - 3) + B
        tmp.copy(x1);
        tmp.modSq(curve.pBN);      // x1^2
        tmp.modSub(precomp_three, curve.pBN);  // x1^2 - 3
        gx1.copy(x1);
        gx1.modMult(tmp, curve.pBN); // x1 * (x1^2 - 3)
        gx1.modAdd(curve.bBN, curve.pBN); // + B

        // Choose x based on which gx is a square
        jcmathlib.BigNat chosenX;  // Will point to x1 or x2

        if (gx1.isQuadraticResidue(curve.pBN)) {
            // gx1 is a square, use x1
            chosenX = x1;
            gx1.modSqrt(curve.pBN);
            y = gx1;  // Reassign y to point to gx1 (no copy needed)
        } else {
            // gx1 is not a square, compute x2 and gx2 only now
            // x2 = Z * u^2 * x1
            // x2 already points to tv1 which contains Z * u^2, no copy needed
            x2.modMult(x1, curve.pBN);

            // gx2 = x2^3 + A*x2 + B
            // For P-256 where A=-3, optimize to: x2(x2^2 - 3) + B
            tmp.copy(x2);
            tmp.modSq(curve.pBN);      // x2^2
            tmp.modSub(precomp_three, curve.pBN);  // x2^2 - 3
            gx2.copy(x2);
            gx2.modMult(tmp, curve.pBN); // x2 * (x2^2 - 3)
            gx2.modAdd(curve.bBN, curve.pBN); // + B

            chosenX = x2;
            gx2.modSqrt(curve.pBN);
            y = gx2;  // Reassign y to point to gx2 (no copy needed)
        }

        // Ensure sgn0(u) == sgn0(y)
        // sgn0 returns the least significant bit (odd = 1, even = 0)
        // Note: sgn0_u was saved at the beginning of this method
        boolean sgn0_y = y.isOdd();

        if (sgn0_u != sgn0_y) {
            y.modNegate(curve.pBN);
        }

        // Construct the point from (x, y)
        // Use the proper uncompressed point format: 0x04 || x || y
        byte[] pointBuffer = curve.rm.POINT_ARRAY_A;
        pointBuffer[0] = (byte) 0x04;

        // Zero the coordinate section once (saves one arrayFill operation)
        Util.arrayFillNonAtomic(pointBuffer, (short) 1, (short) 64, (byte) 0);

        // Write x coordinate to buffer (32 bytes)
        // Copy to tmpBuffer first, then manually pad to avoid prependZeros size issues
        short xLen = chosenX.copyToByteArray(tmpBuffer, (short) 0);
        short xStart = 0;
        while (xStart < xLen && tmpBuffer[xStart] == 0) {
            xStart++;
        }
        short xDataLen = (short) (xLen - xStart);
        if (xDataLen > 32) {
            xDataLen = 32;
            xStart = (short) (xLen - 32);
        }
        short xPadLen = (short) (32 - xDataLen);
        // No need to fill padding - already zeroed above
        Util.arrayCopyNonAtomic(tmpBuffer, xStart, pointBuffer, (short) (1 + xPadLen), xDataLen);

        // Write y coordinate to buffer (32 bytes)
        short yLen = y.copyToByteArray(tmpBuffer, (short) 0);
        short yStart = 0;
        while (yStart < yLen && tmpBuffer[yStart] == 0) {
            yStart++;
        }
        short yDataLen = (short) (yLen - yStart);
        if (yDataLen > 32) {
            yDataLen = 32;
            yStart = (short) (yLen - 32);
        }
        short yPadLen = (short) (32 - yDataLen);
        // No need to fill padding - already zeroed above
        Util.arrayCopyNonAtomic(tmpBuffer, yStart, pointBuffer, (short) (33 + yPadLen), yDataLen);

        // Set the point using setW which validates the point is on the curve
        // POINT_SIZE = 1 + 2*COORD_SIZE = 1 + 2*32 = 65 for P-256
        output.setW(pointBuffer, (short) 0, curve.POINT_SIZE);
    }
}
