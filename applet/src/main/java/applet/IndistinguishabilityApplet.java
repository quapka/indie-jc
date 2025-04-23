package applet;

import javacard.framework.*;
import javacard.security.*;

public class IndistinguishabilityApplet extends Applet
{
	private static final byte[] helloWorld = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!'};
	private static final byte[] Good = {'G', 'O', 'O', 'D'};
	private static final byte[] Bad = {'B', 'A', 'D'};
	private static final byte[] None = {'N', 'o', 'n', 'e'};

    // private static final byte[] OIDC_PRIVKEY = {(byte) 0xa7, (byte) 0xd0, (byte) 0x5b, (byte) 0x9a, (byte) 0x4a, (byte) 0xf4, (byte) 0x9a, (byte) 0xba, (byte) 0x84, (byte) 0xdc, (byte) 0x7b, (byte) 0x98, (byte) 0xa9, (byte) 0x1e, (byte) 0x21, (byte) 0x75, (byte) 0xb9, (byte) 0x47, (byte) 0xf3, (byte) 0x90, (byte) 0x4e, (byte) 0xde, (byte) 0x38, (byte) 0x9a, (byte) 0x28, (byte) 0x8d, (byte) 0xc3, (byte) 0x42, (byte) 0x8f, (byte) 0xd8, (byte) 0x8d, (byte) 0xe6};

    // This is a copy-pasted key from indie-oidc-provider
    private static final byte[] OIDC_PUBLIC_POINT_DATA = {
        (byte) 0x04,
        // x-coordinate
        (byte) 0x2a, (byte) 0x9f, (byte) 0x51, (byte) 0x04,
        (byte) 0xe9, (byte) 0x7b, (byte) 0x40, (byte) 0x82,
        (byte) 0xe6, (byte) 0xf4, (byte) 0xa4, (byte) 0x9b,
        (byte) 0x81, (byte) 0x26, (byte) 0x82, (byte) 0x41,
        (byte) 0xb8, (byte) 0xf5, (byte) 0x39, (byte) 0x21,
        (byte) 0x4b, (byte) 0x14, (byte) 0x4e, (byte) 0xc4,
        (byte) 0xba, (byte) 0xf9, (byte) 0x37, (byte) 0x86,
        (byte) 0x70, (byte) 0xe5, (byte) 0x4e, (byte) 0xaa,
        // y-coordinate
        (byte) 0x4c, (byte) 0xe1, (byte) 0xfc, (byte) 0x4f,
        (byte) 0x4f, (byte) 0x48, (byte) 0x7f, (byte) 0x13,
        (byte) 0x9b, (byte) 0x21, (byte) 0xdf, (byte) 0xe0,
        (byte) 0xd0, (byte) 0x89, (byte) 0x4a, (byte) 0x38,
        (byte) 0xf5, (byte) 0xd4, (byte) 0xfb, (byte) 0xd8,
        (byte) 0xe2, (byte) 0x0c, (byte) 0xfc, (byte) 0xa5,
        (byte) 0x5d, (byte) 0x5e, (byte) 0x62, (byte) 0x2a,
        (byte) 0xc3, (byte) 0x52, (byte) 0x79, (byte) 0xd2
    };

    private KeyPair ecKeyPair;
    private ECPrivateKey privateKey;
    private ECPublicKey publicKey;

    private ECPublicKey OIDC_PUBLIC_KEY = null;

    private short sw = ISO7816.SW_NO_ERROR;

	public static void install(byte[] bArray, short bOffset, byte bLength)
	{
		new IndistinguishabilityApplet();
	}

	public IndistinguishabilityApplet()
	{
		register();
	}

	public void process(APDU apdu)
	{
        byte[] buffer = apdu.getBuffer();
        byte cla = buffer[ISO7816.OFFSET_CLA];
        byte ins = buffer[ISO7816.OFFSET_INS];

        if ( cla == 0x02 ) {
            sendGood(apdu);
        } else if ( cla == 0x04 ) {
            sendBad(apdu);
        } else if ( cla == 0x05 ) {
            sendPrivate(apdu);
        } else if ( cla == 0x06 ) {
            sendPublic(apdu);
        }
		// sendHelloWorld(apdu);
	}

    private void setOIDCPublicKey() {
        OIDC_PUBLIC_KEY = (ECPublicKey) KeyBuilder.buildKey(
            KeyBuilder.TYPE_EC_FP_PUBLIC,
            KeyBuilder.LENGTH_EC_FP_256,
            false
        );

        short offset = 0;
        OIDC_PUBLIC_KEY.setFieldFP(SecP256r1.p, offset, (short) SecP256r1.p.length);
        OIDC_PUBLIC_KEY.setA(SecP256r1.a, offset, (short) SecP256r1.a.length);
        OIDC_PUBLIC_KEY.setB(SecP256r1.b, offset, (short) SecP256r1.b.length);
        OIDC_PUBLIC_KEY.setG(SecP256r1.G, offset, (short) SecP256r1.G.length);
        OIDC_PUBLIC_KEY.setR(SecP256r1.n, offset, (short) SecP256r1.n.length);
        OIDC_PUBLIC_KEY.setK(SecP256r1.h);
        OIDC_PUBLIC_KEY.setW(OIDC_PUBLIC_POINT_DATA, offset, (short) OIDC_PUBLIC_POINT_DATA.length);
    }

    private void generateKeypair()
    {
        ECPrivateKey privateKey = (ECPrivateKey) KeyBuilder.buildKey(
            KeyBuilder.TYPE_EC_FP_PRIVATE,
            KeyBuilder.LENGTH_EC_FP_256,
            false
        );
        ECPublicKey publicKey = (ECPublicKey) KeyBuilder.buildKey(
            KeyBuilder.TYPE_EC_FP_PUBLIC,
            KeyBuilder.LENGTH_EC_FP_256,
            false
        );

         try {
            if ( publicKey == null) {
                ecKeyPair.genKeyPair();
            }
        } catch (Exception e) {
        } // do intentionally nothing

        short offset = 0;

        publicKey.setFieldFP(SecP256r1.p, offset, (short) SecP256r1.p.length);
        publicKey.setA(SecP256r1.a, offset, (short) SecP256r1.a.length);
        publicKey.setB(SecP256r1.b, offset, (short) SecP256r1.b.length);
        publicKey.setG(SecP256r1.G, offset, (short) SecP256r1.G.length);
        publicKey.setR(SecP256r1.n, offset, (short) SecP256r1.n.length);
        publicKey.setK(SecP256r1.h);

        privateKey.setFieldFP(SecP256r1.p, offset, (short) SecP256r1.p.length);
        privateKey.setA(SecP256r1.a, offset, (short) SecP256r1.a.length);
        privateKey.setB(SecP256r1.b, offset, (short) SecP256r1.b.length);
        privateKey.setG(SecP256r1.G, offset, (short) SecP256r1.G.length);
        privateKey.setR(SecP256r1.n, offset, (short) SecP256r1.n.length);
        privateKey.setK(SecP256r1.h);

        ecKeyPair = new KeyPair(publicKey, privateKey);

        ecKeyPair.genKeyPair();
    }

	private void sendPrivate(APDU apdu) {
        sw = ISO7816.SW_NO_ERROR;
        // byte[] privkeyBytes = { 'N', 'o', ' ', 'k', 'e', 'y', ' ', 's', 'e', 't'};
        byte[] privkeyBytes = new byte[KeyBuilder.LENGTH_EC_FP_256];
        byte[] pubkeyBytes = new byte[KeyBuilder.LENGTH_EC_FP_256];
        byte[] buffer = apdu.getBuffer();

        try {

            generateKeypair();

            verifySignature();
            ECPrivateKey privkey = (ECPrivateKey) ecKeyPair.getPrivate();
            // ECPublicKey pubkey = (ECPublicKey) ecKeyPair.getPublic();

            // byte[] S = {'n', (byte) 0x00, (byte) 0xff, (byte) 0xee};
            // privkey.setS(S, (short) 0, (short) 4);

            short length = privkey.getS(buffer, (short) 0);
            // short length = pubkey.getW(pubkeyBytes, (short) 0);

            // short length = (short) privkeyBytes.length;
            // Util.arrayCopyNonAtomic(privkeyBytes, (short) 0, buffer, (short) 0, length);
            apdu.setOutgoingAndSend((short) 0, length);
            //
            // if ( privkey.isInitialized() ) {
            //     Util.arrayCopyNonAtomic(Good, (short) 0, buffer, (short) 0, (short) Good.length);
            //     apdu.setOutgoingAndSend((short) 0, (short) Good.length);
            // } else {
            //     Util.arrayCopyNonAtomic(Bad, (short) 0, buffer, (short) 0, (short) Bad.length);
            //     apdu.setOutgoingAndSend((short) 0, (short) Bad.length);
            // }
        // } catch (CardRuntimeException ce) {
        //     sw = ce.getReason();
        //     // Util.setShort(sw, 2, 0);
        //     // apdu.setOutgoingAndSend((short) 0, length);
        } catch (CryptoException ce) {
            // switch (e.getReason()){
            //     case CryptoException.ILLEGAL_USE:

            // }
            Util.setShort(buffer, (short) 0, ce.getReason());
            // Util.arrayCopyNonAtomic(None, (short) 0, buffer, (short) 0, (short) None.length);
            apdu.setOutgoingAndSend((short) 0, (short) None.length);
        }
	}

    private boolean verifySignature() {
        setOIDCPublicKey();
        Signature sigObj = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        sigObj.init(OIDC_PUBLIC_KEY, Signature.MODE_VERIFY);
        // sibObj.verify();

        return false;
    }

	private void sendPublic(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		short length = (short) Good.length;
		Util.arrayCopyNonAtomic(Good, (short) 0, buffer, (short) 0, length);
		apdu.setOutgoingAndSend((short) 0, length);
	}

	private void sendGood(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		short length = (short) Good.length;
		Util.arrayCopyNonAtomic(Good, (short) 0, buffer, (short) 0, length);
		apdu.setOutgoingAndSend((short) 0, length);
	}

	private void sendBad(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		short length = (short) Bad.length;
		Util.arrayCopyNonAtomic(Bad, (short) 0, buffer, (short) 0, length);
		apdu.setOutgoingAndSend((short) 0, length);
	}

    public static class SecP256r1 {
        public final static byte[] p = {
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff
        };
        public final static byte[] a = {
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x01,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xfc
        };
        public final static byte[] b = {
            (byte) 0x5a, (byte) 0xc6, (byte) 0x35, (byte) 0xd8,
            (byte) 0xaa, (byte) 0x3a, (byte) 0x93, (byte) 0xe7,
            (byte) 0xb3, (byte) 0xeb, (byte) 0xbd, (byte) 0x55,
            (byte) 0x76, (byte) 0x98, (byte) 0x86, (byte) 0xbc,
            (byte) 0x65, (byte) 0x1d, (byte) 0x06, (byte) 0xb0,
            (byte) 0xcc, (byte) 0x53, (byte) 0xb0, (byte) 0xf6,
            (byte) 0x3b, (byte) 0xce, (byte) 0x3c, (byte) 0x3e,
            (byte) 0x27, (byte) 0xd2, (byte) 0x60, (byte) 0x4b
        };
        public final static byte[] G = {
            (byte) 0x04,
            // x-coordinate
            (byte) 0x6b, (byte) 0x17, (byte) 0xd1, (byte) 0xf2,
            (byte) 0xe1, (byte) 0x2c, (byte) 0x42, (byte) 0x47,
            (byte) 0xf8, (byte) 0xbc, (byte) 0xe6, (byte) 0xe5,
            (byte) 0x63, (byte) 0xa4, (byte) 0x40, (byte) 0xf2,
            (byte) 0x77, (byte) 0x03, (byte) 0x7d, (byte) 0x81,
            (byte) 0x2d, (byte) 0xeb, (byte) 0x33, (byte) 0xa0,
            (byte) 0xf4, (byte) 0xa1, (byte) 0x39, (byte) 0x45,
            (byte) 0xd8, (byte) 0x98, (byte) 0xc2, (byte) 0x96,
            // y-coordinate
            (byte) 0x4f, (byte) 0xe3, (byte) 0x42, (byte) 0xe2,
            (byte) 0xfe, (byte) 0x1a, (byte) 0x7f, (byte) 0x9b,
            (byte) 0x8e, (byte) 0xe7, (byte) 0xeb, (byte) 0x4a,
            (byte) 0x7c, (byte) 0x0f, (byte) 0x9e, (byte) 0x16,
            (byte) 0x2b, (byte) 0xce, (byte) 0x33, (byte) 0x57,
            (byte) 0x6b, (byte) 0x31, (byte) 0x5e, (byte) 0xce,
            (byte) 0xcb, (byte) 0xb6, (byte) 0x40, (byte) 0x68,
            (byte) 0x37, (byte) 0xbf, (byte) 0x51, (byte) 0xf5
        };
        // the order of G
        public final static byte[] n = {
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
            (byte) 0xbc, (byte) 0xe6, (byte) 0xfa, (byte) 0xad,
            (byte) 0xa7, (byte) 0x17, (byte) 0x9e, (byte) 0x84,
            (byte) 0xf3, (byte) 0xb9, (byte) 0xca, (byte) 0xc2,
            (byte) 0xfc, (byte) 0x63, (byte) 0x25, (byte) 0x51
        };
        // cofactor
        public final static short h = 0x01;
    }
}
