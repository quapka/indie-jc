package applet;

import javacard.framework.Util;
import javacard.framework.CardRuntimeException;

public class Utils {

    private Utils() {}

    private static final short NIBBLE_SIZE = 4;

    public static final short REASON_DATA_BUFFER_NOT_LARGE_ENOUGH = 0x0001;
    public static final short REASON_INVALID_ENCODING_SIZE = 0x0002;
    public static final short REASON_INVALID_ENCODING_CHARACTER = 0x0003;
    public static final short REASON_INVALID_DATA_SIZE = 0x0004;

    public static byte derEncodeRawEcdsaSignature(byte[] signature, byte[] out) {
        // SEQUENCE
        byte index = 0;
        out[index++] = 0x30;
        // NOTE assuming P256
        short rLen = 32;
        short sLen = 32;

        // byte mask = 0x80;

        // NOTE maybe flip == 0 to != 0?
        if ( (/* r[0] */ signature[0] & (byte) 0x80) == (byte) 0x80 ) {
            rLen += 1;
        }
        if ( (/* s[0] */ signature[32] & (byte) 0x80) == (byte) 0x80 ) {
            sLen += 1;
        }
        // FIXME sequenceLen is byte
        short sequenceLen = (short) 2;
        sequenceLen += rLen;
        sequenceLen += (short) 2;
        sequenceLen += sLen;

        // short wholeLen = sequenceLen;
        // wholeLen += (short) 1;

        out[index++] = (byte) sequenceLen;
        out[index++] = (byte) 0x02;
        out[index++] = (byte) rLen;

        if ( (/* r[0] */ signature[0] & (byte) 0x80) == (byte) 0x80 ) {
            out[index++] = (byte) 0x00;
        }

        // copy r value
        Util.arrayCopyNonAtomic(signature, (short) 0, out, index, (short) 32);
        index += 32;

        out[index++] = (byte) 0x02;
        out[index++] = (byte) sLen;
        
        if ( (/* s[0] */ signature[32] & (byte) 0x80) == (byte) 0x80 ) {
            out[index++] = (byte) 0x00;
        }

        // copy s value
        Util.arrayCopyNonAtomic(signature, (short) 32, out, index, (short) 32);
        index += 32;
        return index;
    }

    /**
     * Decodes the hexadecimal encoded bytes in the input buffer and puts them
     * in the output buffer.
     * Hex digits need to be ASCII encoded and the letters need to be uppercase.
     * Each byte needs to be encoded using exactly two hexadecimal digits.
     * WARNING: this function doesn't currently validate offset and length
     * arguments.
     *
     * Kudos to: Maarten Bodewes https://stackoverflow.com/a/41293362/2377489
     *
     * @param in
     *            the input buffer
     * @param inOff
     *            the offset in the input buffer containing the hexadecimal
     *            bytes
     * @param inLen
     *            the length in the input buffer of the hexadecimal bytes
     * @param out
     *            the output buffer
     * @param outOff
     *            the offset in the output buffer of the decoded bytes
     * @return the length in the output buffer of the decoded bytes
     * @throws CardRuntimeException
     *             with the following reason codes:
     *             <nl>
     *             <li>
     *             {@link HexCodec#REASON_INVALID_ENCODING_SIZE} : if the
     *             encoding size is not a multiple of 2</li>
     *             <li>
     *             {@link HexCodec#REASON_DATA_BUFFER_NOT_LARGE_ENOUGH} : if
     *             the output buffer cannot hold the decoded data</li>
     *             <li>
     *             {@link HexCodec#REASON_INVALID_ENCODING_CHARACTER} : if
     *             the encoding contains characters outside the uppercase
     *             hexadecimals</li>
     *             </nl>
     */
    public static short fromUppercaseHex(final byte[] in, final short inOff,
            final short inLen,
            final byte[] out, final short outOff) {

        // doesn't validate offsets in buffer

        // odd number of hex characters not allowed
        if (inLen % 2 != 0) {
            throw createCardRuntimeException(REASON_INVALID_ENCODING_SIZE);
        }

        final short outLen = (short) (inLen / 2);

        // make sure we have enough room in the buffer *before* decoding
        final short outEnd = (short) (outOff + outLen);
        if (outEnd < 0
                || outEnd > (short) out.length) {
            throw createCardRuntimeException(REASON_DATA_BUFFER_NOT_LARGE_ENOUGH);
        }

        // main decode loop
        for (short i = 0; i < outLen; i++) {
            byte b;

            // decodes high nibble of b
            final byte hexHi = in[(short) (inOff + i * 2)];
            if (hexHi >= '0' && hexHi <= '9') {
                b = (byte) ((hexHi - '0') << NIBBLE_SIZE);
            } else if (hexHi >= 'A' && hexHi <= 'F') {
                b = (byte) ((hexHi - 'A' + 10) << NIBBLE_SIZE);
            } else {
                throw createCardRuntimeException(REASON_INVALID_ENCODING_CHARACTER);
            }

            // decodes low nibble of b
            final byte hexLo = in[(short) (inOff + i * 2 + 1)];
            if (hexLo >= '0' && hexLo <= '9') {
                b |= (byte) (hexLo - '0');
            } else if (hexLo >= 'A' && hexLo <= 'F') {
                b |= (byte) (hexLo - 'A' + 10);
            } else {
                throw createCardRuntimeException(REASON_INVALID_ENCODING_CHARACTER);
            }

            out[(short) (outOff + i)] = b;
        }

        return outLen;
    }

    /**
     * Encodes the bytes in the input buffer and puts the hexadecimals in the
     * output buffer.
     * The hex digits will be ASCII encoded and the letters will be in
     * uppercase.
     * Each byte will be encoded using exactly two hexadecimal digits.
     * WARNING: this function doesn't currently validate offset and length
     * arguments.
     *
     * @param in
     *            the input buffer
     * @param inOff
     *            the offset in the input buffer containing the binary data
     *            bytes
     * @param inLen
     *            the length in the input buffer of the binary data
     * @param out
     *            the output buffer
     * @param outOff
     *            the offset in the output buffer for the hexadecimal digits
     * @return the number of hexadecimal digits
     * @throws CardRuntimeException
     *             with the following reason codes:
     *             <nl>
     *             <li>
     *             {@link HexCodec#REASON_INVALID_DATA_SIZE} : if the output
     *             buffer cannot hold the encoded data</li>
     *             </nl>
     */
    private static short toUppercaseHex(
            final byte[] in, final short inOff, final short inLen,
            final byte[] out, final short outOff) {

        // doesn't validate offsets in buffer

        final short outLen = (short) (inLen * 2);
        final short outEnd = (short) (outOff + outLen);

        // make sure we have enough room in the buffer *before* decoding
        if (outEnd < 0 || outEnd > (short) out.length) {
            throw createCardRuntimeException(REASON_INVALID_DATA_SIZE);
        }

        // main encode loop
        for (short i = 0; i < inLen; i++) {
            final byte b = in[(short) (inOff + i)];

            // encodes high nibble of b
            final byte bHi = (byte) ((b >> NIBBLE_SIZE) & 0x0F);
            if (bHi < 10) {
                out[(short) (outOff + i * 2)] = (byte) ('0' + bHi);
            } else {
                out[(short) (outOff + i * 2)] = (byte) ('A' + bHi - 10);
            }

            // encodes low nibble of b
            final byte bLo = (byte) (b & 0x0F);
            if (bLo < 10) {
                out[(short) (outOff
                        + i * 2 + 1)] = (byte) ('0' + bLo);
            } else {
                out[(short) (outOff
                        + i * 2 + 1)] = (byte) ('A' + bLo - 10);
            }
        }

        return outLen;
    }

    /**
     * Creates a CardRuntimeException with the given reason code and returns it
     * so it can be thrown.
     * This alleviates the issue of the Java compiler not recognizing `throwIt`
     * as exit point.
     * WARNING: do not forget to actually throw the exception returned.
     *
     * @param reason
     *            the reason code of the exception
     * @return the exception generated by the runtime environment (through
     *         <code>CardRuntimeException.throwIt</code>)
     */
    private static CardRuntimeException createCardRuntimeException(
            final short reason) {
        try {
            CardRuntimeException.throwIt(reason);
        } catch (CardRuntimeException e) {
            return e;
        }
        // should never be reached (but the compiler doesn't know that)
        return null;
    }

}
