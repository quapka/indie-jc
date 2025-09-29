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

        // NOTE the following are debug instructions
        public static final byte GOOD = (byte) 0x88;
        public static final byte BAD = (byte) 0x99;
        public static final byte COMPUTE_MOD_MULT = (byte) 0xaa;
    }
    // TODO: add the list from https://www.eftlab.com/knowledge-base/complete-list-of-apdu-responses
    public class SW {
        public static final short OK = (short) 0x9000;
    }
}
