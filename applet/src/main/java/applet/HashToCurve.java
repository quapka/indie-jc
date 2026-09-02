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
    private final byte[] dstPrimeBuffer = JCSystem.makeTransientByteArray((short) 45, JCSystem.CLEAR_ON_RESET); // DST length + 1
    private final byte[] tmpBuffer = JCSystem.makeTransientByteArray((short) 64, JCSystem.CLEAR_ON_RESET);

    // RFC 9380 dedicated BigNats (persistent memory, sized appropriately)
    // These are used exclusively for hash-to-curve to avoid conflicts with ResourceManager BigNats
    private jcmathlib.BigNat rfc_u0;      // Field element from first 48 bytes (32 bytes for P-256)
    private jcmathlib.BigNat rfc_u1;      // Field element from second 48 bytes (32 bytes for P-256)
    private jcmathlib.BigNat rfc_tmp;     // Temporary for 48-byte values (48 bytes)
    private jcmathlib.BigNat rfc_Z;       // Constant Z = -10
    private jcmathlib.BigNat rfc_tv1;     // Temporary variable 1
    private jcmathlib.BigNat rfc_tv2;     // Temporary variable 2
    private jcmathlib.BigNat rfc_x1;      // x1 candidate
    private jcmathlib.BigNat rfc_x2;      // x2 candidate
    private jcmathlib.BigNat rfc_gx1;     // g(x1)
    private jcmathlib.BigNat rfc_gx2;     // g(x2)
    private jcmathlib.BigNat rfc_y;       // y coordinate
    private jcmathlib.BigNat rfc_work;    // General work variable

    public HashToCurve() {
        // Initialize RFC9380 BigNats in TRANSIENT memory (allows resizing during operations)
        // Use 48 bytes for rfc_tmp to hold the 48-byte field element before reduction
        // Use 32 bytes for all others (sufficient for P-256 field elements)
        rfc_tmp = new jcmathlib.BigNat((short) 48, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, IndistinguishabilityApplet.rm);
        rfc_u0 = new jcmathlib.BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, IndistinguishabilityApplet.rm);
        rfc_u1 = new jcmathlib.BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, IndistinguishabilityApplet.rm);
        rfc_Z = new jcmathlib.BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, IndistinguishabilityApplet.rm);
        rfc_tv1 = new jcmathlib.BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, IndistinguishabilityApplet.rm);
        rfc_tv2 = new jcmathlib.BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, IndistinguishabilityApplet.rm);
        rfc_x1 = new jcmathlib.BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, IndistinguishabilityApplet.rm);
        rfc_x2 = new jcmathlib.BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, IndistinguishabilityApplet.rm);
        rfc_gx1 = new jcmathlib.BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, IndistinguishabilityApplet.rm);
        rfc_gx2 = new jcmathlib.BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, IndistinguishabilityApplet.rm);
        rfc_y = new jcmathlib.BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, IndistinguishabilityApplet.rm);
        rfc_work = new jcmathlib.BigNat((short) 32, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, IndistinguishabilityApplet.rm);
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
        // DST_prime = DST || I2OSP(len(DST), 1)
        Util.arrayCopyNonAtomic(RFC9380_DST, (short) 0, dstPrimeBuffer, (short) 0, (short) RFC9380_DST.length);
        dstPrimeBuffer[RFC9380_DST.length] = (byte) RFC9380_DST.length;

        // Compute b_0 = H(Z_pad || msg || I2OSP(len_in_bytes, 2) || I2OSP(0, 1) || DST_prime)
        // Z_pad is 64 zero bytes (SHA-256 block size)
        md.reset();
        // Add 64 zero bytes
        Util.arrayFillNonAtomic(tmpBuffer, (short) 0, (short) 64, (byte) 0);
        md.update(tmpBuffer, (short) 0, (short) 64);
        // Add message
        md.update(msg, msgOffset, msgLength);
        // Add I2OSP(96, 2) - length in bytes
        tmpBuffer[0] = (byte) 0x00;
        tmpBuffer[1] = (byte) 0x60; // 96 in hex
        md.update(tmpBuffer, (short) 0, (short) 2);
        // Add I2OSP(0, 1)
        tmpBuffer[0] = (byte) 0x00;
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
        // XOR b_0 with b_1 into tmpBuffer
        for (short i = 0; i < 32; i++) {
            tmpBuffer[i] = (byte) (b0Buffer[i] ^ expandBuffer[i]);
        }
        md.reset();
        md.update(tmpBuffer, (short) 0, (short) 32);
        tmpBuffer[0] = (byte) 0x02;
        md.update(tmpBuffer, (short) 0, (short) 1);
        md.update(dstPrimeBuffer, (short) 0, (short) (RFC9380_DST.length + 1));
        md.doFinal(tmpBuffer, (short) 0, (short) 0, expandBuffer, (short) 32);

        // Compute b_3 = H(b_0 XOR b_2 || I2OSP(3, 1) || DST_prime)
        // XOR b_0 with b_2 into tmpBuffer
        for (short i = 0; i < 32; i++) {
            tmpBuffer[i] = (byte) (b0Buffer[i] ^ expandBuffer[(short) (32 + i)]);
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

        // Step 2: Convert uniform bytes to two field elements u0 and u1
        // Load u0 via rfc_tmp
        rfc_tmp.fromByteArray(expandBuffer, (short) 0, (short) 48);
        rfc_tmp.mod(curve.pBN);
        rfc_u0.copy(rfc_tmp);

        // Step 3: Map u0 to first curve point, store in output
        mapToSswu(rfc_u0, output);

        // Load u1 via rfc_tmp
        rfc_tmp.fromByteArray(expandBuffer, (short) 48, (short) 48);
        rfc_tmp.mod(curve.pBN);
        rfc_u1.copy(rfc_tmp);

        // Step 4: Map u1 to second curve point
        // We need a temporary point - create it and map u1 to it
        jcmathlib.ECPoint P1 = new jcmathlib.ECPoint(curve);
        mapToSswu(rfc_u1, P1);

        // Step 5: Add the points: output = P0 + P1
        output.add(P1);

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

        // Z = -10 = p - 10
        Z.copy(curve.pBN);
        tmp.setValue((byte) 10);
        Z.modSub(tmp, curve.pBN);

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
        } else {
            tv2.zero();
        }

        // x1 = (-B / A) * (1 + tv2)
        x1.copy(curve.bBN);
        tmp.setValue((byte) 3);
        tmp.modInv(curve.pBN);
        x1.modMult(tmp, curve.pBN);  // x1 = B/3

        tmp.setValue((byte) 1);
        tmp.modAdd(tv2, curve.pBN);   // tmp = 1 + tv2
        x1.modMult(tmp, curve.pBN);   // x1 = (B/3) * (1 + tv2)

        // gx1 = x1^3 + A*x1 + B
        gx1.copy(x1);
        gx1.modSq(curve.pBN);      // x1^2
        gx1.modMult(x1, curve.pBN); // x1^3
        tmp.copy(curve.aBN);
        tmp.modMult(x1, curve.pBN);
        gx1.modAdd(tmp, curve.pBN); // + A*x1
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

        // Z = -10 = p - 10
        Z.copy(curve.pBN);
        tmp.setValue((byte) 10);
        Z.modSub(tmp, curve.pBN);

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
        } else {
            tv2.zero();
        }

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
        jcmathlib.ECCurve curve = IndistinguishabilityApplet.curve;

        // Compute Z = p - 10
        jcmathlib.BigNat Z = rfc_Z;
        jcmathlib.BigNat tmp = rfc_work;

        Z.copy(curve.pBN);
        tmp.setValue((byte) 10);
        Z.modSub(tmp, curve.pBN);

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
        jcmathlib.BigNat Z = rfc_Z;
        jcmathlib.BigNat tv1 = rfc_tv1;
        jcmathlib.BigNat tv2 = rfc_tv2;
        jcmathlib.BigNat x1 = rfc_x1;
        jcmathlib.BigNat x2 = rfc_x2;
        jcmathlib.BigNat gx1 = rfc_gx1;
        jcmathlib.BigNat gx2 = rfc_gx2;
        jcmathlib.BigNat y = rfc_y;
        jcmathlib.BigNat tmp = rfc_work;

        // Save u's oddness (u is already in a dedicated BigNat, so it's safe)
        boolean sgn0_u = u.isOdd();

        // Z = -10 = p - 10
        Z.copy(curve.pBN);
        tmp.setValue((byte) 10);
        Z.modSub(tmp, curve.pBN);

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

        // tv2 = inv0(tv2) - compute modular inverse if tv2 != 0, else 0
        boolean tv2IsZero = tv2.isZero();
        if (!tv2IsZero) {
            tv2.modInv(curve.pBN);
        } else {
            tv2.zero();
        }

        // x1 = (-B / A) * (1 + tv2)
        // For P-256: A = -3, B = curve.b
        // -B/A = B/3
        x1.copy(curve.bBN);
        tmp.setValue((byte) 3);
        tmp.modInv(curve.pBN);
        x1.modMult(tmp, curve.pBN);  // x1 = B/3

        tmp.setValue((byte) 1);
        tmp.modAdd(tv2, curve.pBN);   // tmp = 1 + tv2
        x1.modMult(tmp, curve.pBN);   // x1 = (B/3) * (1 + tv2)

        // If tv2 == 0, set x1 = B / (Z * A)
        // For P-256: A = -3, so Z * A = Z * (-3) = -3Z
        if (tv2IsZero) {
            x1.copy(curve.bBN);       // x1 = B
            tmp.copy(Z);
            tmp.modMult(curve.aBN, curve.pBN);  // tmp = Z * A
            tmp.modInv(curve.pBN);     // tmp = 1 / (Z * A)
            x1.modMult(tmp, curve.pBN); // x1 = B / (Z * A)
        }

        // gx1 = x1^3 + A*x1 + B
        gx1.copy(x1);
        gx1.modSq(curve.pBN);      // x1^2
        gx1.modMult(x1, curve.pBN); // x1^3
        tmp.copy(curve.aBN);
        tmp.modMult(x1, curve.pBN);
        gx1.modAdd(tmp, curve.pBN); // + A*x1
        gx1.modAdd(curve.bBN, curve.pBN); // + B

        // x2 = Z * u^2 * x1
        x2.copy(Z);
        tmp.copy(u);
        tmp.modSq(curve.pBN);
        x2.modMult(tmp, curve.pBN);
        x2.modMult(x1, curve.pBN);

        // gx2 = x2^3 + A*x2 + B
        gx2.copy(x2);
        gx2.modSq(curve.pBN);
        gx2.modMult(x2, curve.pBN);
        tmp.copy(curve.aBN);
        tmp.modMult(x2, curve.pBN);
        gx2.modAdd(tmp, curve.pBN);
        gx2.modAdd(curve.bBN, curve.pBN);

        // Choose x based on which gx is a square
        // y is already defined as rfc_y at the top
        jcmathlib.BigNat chosenX;  // Will point to x1 or x2

        y.copy(gx1);
        if (y.isQuadraticResidue(curve.pBN)) {
            // gx1 is a square, use x1
            chosenX = x1;
            y.copy(gx1);
            y.modSqrt(curve.pBN);
        } else {
            // gx1 is not a square, use x2
            chosenX = x2;
            y.copy(gx2);
            y.modSqrt(curve.pBN);
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
        Util.arrayFillNonAtomic(pointBuffer, (short) 1, xPadLen, (byte) 0);
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
        Util.arrayFillNonAtomic(pointBuffer, (short) 33, yPadLen, (byte) 0);
        Util.arrayCopyNonAtomic(tmpBuffer, yStart, pointBuffer, (short) (33 + yPadLen), yDataLen);

        // Set the point using setW which validates the point is on the curve
        // POINT_SIZE = 1 + 2*COORD_SIZE = 1 + 2*32 = 65 for P-256
        output.setW(pointBuffer, (short) 0, curve.POINT_SIZE);
    }
}
