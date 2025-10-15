package applet;

public class Consts {
    public class CLA {
        public static final byte INDIE = (byte) 0x00;
        // FIXME use debug class when appropriate to separate the usages
        public static final byte DEBUG = (byte) 0x88;
    }
    public class INS {
        public static final byte GET_VERIFICATION_PUBKEY = (byte) 0x00;
        public static final byte GET_EXAMPLE_PROOF = (byte) 0x01;
        public static final byte KEY_GEN = (byte) 0x02;
        public static final byte SETUP = (byte) 0x03;
        public static final byte GET_SETUP = (byte) 0x04;
        // Set the uncompressed P256 public key for the JWT signature verification
        public static final byte SET_OIDC_PUBKEY = (byte) 0x05;

        // NOTE the following are debug instructions
        public static final byte GOOD = (byte) 0x88;
        public static final byte BAD = (byte) 0x99;
        public static final byte COMPUTE_MOD_MULT = (byte) 0xaa;
        public static final byte AEAD_DECRYPT = (byte) 0x04;
        public static final byte VERIFY_COMMITMENT = (byte) 0x05;
    }
    // TODO: add the list from https://www.eftlab.com/knowledge-base/complete-list-of-apdu-responses
    public class SW {
        public static final short OK = (short) 0x9000;
    }

    public class ERR {
        public static final short SW_EXCEPTION = (short) 0xe000;
        public static final short AEAD_INVALID_INIT = (short) 0xe001;
        public static final short AEAD_UNINITIALIZED_KEY = (short) 0xe002;
        public static final short AEAD_ILLEGAL_USE = (short) 0xe003;
    }

    public final static short SW_Exception = (short) 0xff01;
    public final static short SW_ArrayIndexOutOfBoundsException = (short) 0xff02;
    public final static short SW_ArithmeticException = (short) 0xff03;
    public final static short SW_ArrayStoreException = (short) 0xff04;
    public final static short SW_NullPointerException = (short) 0xff05;
    public final static short SW_NegativeArraySizeException = (short) 0xff06;
    public final static short SW_CryptoException_prefix = (short) 0xf100;
    public final static short SW_SystemException_prefix = (short) 0xf200;
    public final static short SW_PINException_prefix = (short) 0xf300;
    public final static short SW_TransactionException_prefix = (short) 0xf400;
    public final static short SW_CardRuntimeException_prefix = (short) 0xf500;
}
