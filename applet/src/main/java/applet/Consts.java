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
    }
}
