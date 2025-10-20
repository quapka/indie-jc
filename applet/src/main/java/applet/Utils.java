package applet;

import javacard.framework.Util;

public class Utils {

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
}
