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
    private final MessageDigest md = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
    private final byte[] prefixBuffer = JCSystem.makeTransientByteArray((short) 36, JCSystem.CLEAR_ON_RESET);
    private final byte[] ramArray = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_RESET);

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
}
