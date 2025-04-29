package applet;

import java.util.*;

import javacard.framework.*;
import javacardx.framework.util.*;
// import javacard.framework.util.ArrayLogic;
import javacardx.apdu.ExtendedLength;
import javacard.security.*;

import applet.Base64UrlSafeDecoder.*;

public class IndistinguishabilityApplet extends Applet implements ExtendedLength
{
	private static final byte[] helloWorld = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!'};
	private static final byte[] Good = {'G', 'O', 'O', 'D'};
	private static final byte[] Bad = {'B', 'A', 'D'};
	private static final byte[] None = {'N', 'o', 'n', 'e'};

    private byte[] salt = new byte[32];
	private byte[] derSignature = new byte[71];

	private static final byte[] NONCE_FIELD_NAME = {'n', 'o', 'n', 'c', 'e'};
	private static final byte[] AUD_FIELD_NAME = {'a', 'u', 'd'};
	private static final byte[] NAME_FIELD_NAME = {'n', 'a', 'm', 'e'};

	private static final byte[] HASH_SECRET_DOMAIN_SEPARATOR = {'S', 'a', 'l', 't', ' ', 's', 'e', 'r', 'v', 'i', 'c', 'e'};

    // indie-service HASH_SALT_SECRET
    private static final byte[] HASH_SALT_SECRET = {
        (byte) 0x89, (byte) 0x52, (byte) 0xd7, (byte) 0xb3,
        (byte) 0x7e, (byte) 0x1c, (byte) 0x86, (byte) 0x0c,
        (byte) 0x88, (byte) 0xb8, (byte) 0xa5, (byte) 0xdc,
        (byte) 0x19, (byte) 0x62, (byte) 0x19, (byte) 0xd5,
        (byte) 0x07, (byte) 0xdc, (byte) 0xd6, (byte) 0xb6,
        (byte) 0xe2, (byte) 0x59, (byte) 0xdb, (byte) 0x03,
        (byte) 0xb9, (byte) 0xe9, (byte) 0x1a, (byte) 0x4a,
        (byte) 0x24, (byte) 0xfc, (byte) 0xe9, (byte) 0xb4 
    };

    private byte[] tokenNonce = new byte[32];

	private byte[] extApduBuffer = new byte[2048];
	private byte[] procBuffer = new byte[2048];
	private short extApduSize = 0;

    // FIXME remove
    private static final byte[] precomputedDigest = {
        (byte) 0x21, (byte) 0xc6, (byte) 0x73, (byte) 0x68,
        (byte) 0xf4, (byte) 0x36, (byte) 0x57, (byte) 0x7f,
        (byte) 0x44, (byte) 0x7f, (byte) 0x80, (byte) 0x51,
        (byte) 0x62, (byte) 0xca, (byte) 0x13, (byte) 0xb8,
        (byte) 0x0d, (byte) 0x04, (byte) 0x6a, (byte) 0x3f,
        (byte) 0xe4, (byte) 0x67, (byte) 0x24, (byte) 0x7e,
        (byte) 0x65, (byte) 0xea, (byte) 0x47, (byte) 0x7a,
        (byte) 0xa7, (byte) 0x50, (byte) 0xfa, (byte) 0x2e
    };

    // FIXME remove
    private static final byte[] derEncodedSignature = {
        // der first
        (byte) 0x30, (byte) 0x45, (byte) 0x02, (byte) 0x20,
        // r
        (byte) 0x0e, (byte) 0xd1, (byte) 0x21, (byte) 0x53,
        (byte) 0x79, (byte) 0x63, (byte) 0x6c, (byte) 0x48,
        (byte) 0x3c, (byte) 0x2f, (byte) 0x7f, (byte) 0x15,
        (byte) 0x58, (byte) 0x07, (byte) 0xd4, (byte) 0x02,
        (byte) 0xa3, (byte) 0xb2, (byte) 0x28, (byte) 0x03,
        (byte) 0x3a, (byte) 0xf9, (byte) 0x7c, (byte) 0x7e,
        (byte) 0x17, (byte) 0x81, (byte) 0x9a, (byte) 0xc3,
        (byte) 0x16, (byte) 0x9e, (byte) 0xa6, (byte) 0x65,
        // der second
        (byte) 0x02, (byte) 0x21, (byte) 0x00,
        // s
        (byte) 0xc5,
        (byte) 0x0a, (byte) 0x07, (byte) 0xd3, (byte) 0x8c,
        (byte) 0x3c, (byte) 0x70, (byte) 0xe5, (byte) 0xd8,
        (byte) 0xf1, (byte) 0x2d, (byte) 0xaf, (byte) 0x08,
        (byte) 0x4a, (byte) 0x54, (byte) 0x80, (byte) 0xa6,
        (byte) 0x65, (byte) 0x90, (byte) 0xc5, (byte) 0xf2,
        (byte) 0x93, (byte) 0x50, (byte) 0x9a, (byte) 0x8f,
        (byte) 0x3f, (byte) 0x7f, (byte) 0x8a, (byte) 0x83,
        (byte) 0xa3, (byte) 0x54, (byte) 0xd5
    };


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

    // private static final byte[] OIDC_PUBLIC_POINT_DATA = {
    //     // uncompressed point
    //     (byte) 0x04,
    //     // x-coordinater
    //     (byte) 0x7f, (byte) 0xcd, (byte) 0xce, (byte) 0x27,
    //     (byte) 0x70, (byte) 0xf6, (byte) 0xc4, (byte) 0x5d,
    //     (byte) 0x41, (byte) 0x83, (byte) 0xcb, (byte) 0xee,
    //     (byte) 0x6f, (byte) 0xdb, (byte) 0x4b, (byte) 0x7b,
    //     (byte) 0x58, (byte) 0x07, (byte) 0x33, (byte) 0x35,
    //     (byte) 0x7b, (byte) 0xe9, (byte) 0xef, (byte) 0x13,
    //     (byte) 0xba, (byte) 0xcf, (byte) 0x6e, (byte) 0x3c,
    //     (byte) 0x7b, (byte) 0xd1, (byte) 0x54, (byte) 0x45,
    //     // y-coordinate
    //     (byte) 0xc7, (byte) 0xf1, (byte) 0x44, (byte) 0xcd,
    //     (byte) 0x1b, (byte) 0xbd, (byte) 0x9b, (byte) 0x7e,
    //     (byte) 0x87, (byte) 0x2c, (byte) 0xdf, (byte) 0xed,
    //     (byte) 0xb9, (byte) 0xee, (byte) 0xb9, (byte) 0xf4,
    //     (byte) 0xb3, (byte) 0x69, (byte) 0x5d, (byte) 0x6e,
    //     (byte) 0xa9, (byte) 0x0b, (byte) 0x24, (byte) 0xad,
    //     (byte) 0x8a, (byte) 0x46, (byte) 0x23, (byte) 0x28,
    //     (byte) 0x85, (byte) 0x88, (byte) 0xe5, (byte) 0xad
    // };

    private boolean initialized = false;

    private KeyPair ecKeyPair;
    private ECPrivateKey privateKey;
    private ECPublicKey publicKey;

    private ECPublicKey OIDC_PUBLIC_KEY = null;

    private short sw = ISO7816.SW_NO_ERROR;
    private Base64UrlSafeDecoder base64UrlSafeDecoder;

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
        if ( !initialized ) {
            initialize();
        }

        byte[] buffer = apdu.getBuffer();
        byte cla = buffer[ISO7816.OFFSET_CLA];
        byte ins = buffer[ISO7816.OFFSET_INS];
        byte p1 = buffer[ISO7816.OFFSET_P1];
        byte p2 = buffer[ISO7816.OFFSET_P2];

        if ( cla == 0x02 ) {
            sendGood(apdu);
        } else if ( cla == 0x04 ) {
            sendBad(apdu);
        } else if ( cla == 0x05 ) {
            sendPrivate(apdu);
        } else if ( cla == 0x06 ) {
            sendPublic(apdu);
        // } else if ( cla == 0x07 ) {
        //     parseJWT(apdu);
        } else if ( ins == 0x01 ) {
            if ( p1 == 0x00 ) {
                echo(apdu);
            } else if ( p1 == 0x01 ) {
                echo(apdu);
            }
        } else if ( ins == 0x02 ) {
            if ( p1 == 0x00 ) {
                decode(apdu);
            } else if ( p1 == 0x01 ) {
                findValue(apdu);
            }
        } else if ( ins == 0x03 ) {
            deriveSalt(apdu);
        }
	}

    private void initialize() {
        base64UrlSafeDecoder = new Base64UrlSafeDecoder();
        initialized = true;
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

    public short deriveHashSecret(byte[] body, short bodySize, APDU apdu) {
        // FIXME do not allocate buffers here
        byte[] valueBuf = new byte[64];

        MessageDigest hasher = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        hasher.update(HASH_SECRET_DOMAIN_SEPARATOR, (short) 0, (short) HASH_SECRET_DOMAIN_SEPARATOR.length);

        short valueLen = getStringValueFor(body, (short) 0, bodySize, AUD_FIELD_NAME, valueBuf, (short) 0);
        hasher.update(valueBuf, (short) 0, valueLen);

        valueLen = getStringValueFor(body, (short) 0, bodySize, NAME_FIELD_NAME, valueBuf, (short) 0);
        hasher.update(valueBuf, (short) 0, valueLen);
        // hasher.update(HASH_SALT_SECRET, (short) 0, (short) HASH_SALT_SECRET.length);

		byte[] apduBuffer = apdu.getBuffer();
        hasher.doFinal(HASH_SALT_SECRET, (short) 0, (short) HASH_SALT_SECRET.length, apduBuffer, (short) 0);
        return hasher.getLength();

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

    private void encodeSignatureAsDer(byte[] r_s_buffer) {
        // the DER encoding cannot be hardcoded, but needs to be calculated, unfortunately
        // likely, could be done at the client though.
    }

	private void sendPrivate(APDU apdu) {
        sw = ISO7816.SW_NO_ERROR;
        // byte[] privkeyBytes = { 'N', 'o', ' ', 'k', 'e', 'y', ' ', 's', 'e', 't'};
        byte[] privkeyBytes = new byte[KeyBuilder.LENGTH_EC_FP_256];
        byte[] pubkeyBytes = new byte[KeyBuilder.LENGTH_EC_FP_256];
        byte[] buffer = apdu.getBuffer();

        try {

            generateKeypair();
            ECPrivateKey privkey = (ECPrivateKey) ecKeyPair.getPrivate();
            // ECPublicKey pubkey = (ECPublicKey) ecKeyPair.getPublic();

            // byte[] S = {'n', (byte) 0x00, (byte) 0xff, (byte) 0xee};
            // privkey.setS(S, (short) 0, (short) 4);

            // short length = privkey.getS(buffer, (short) 0);
            // short length = pubkey.getW(pubkeyBytes, (short) 0);

            // short length = (short) privkeyBytes.length;
            // Util.arrayCopyNonAtomic(privkeyBytes, (short) 0, buffer, (short) 0, length);
            // apdu.setOutgoingAndSend((short) 0, length);
            //
            if ( verifySignaturePrehashed() ) {
                Util.arrayCopyNonAtomic(Good, (short) 0, buffer, (short) 0, (short) Good.length);
                apdu.setOutgoingAndSend((short) 0, (short) Good.length);
            } else {
                Util.arrayCopyNonAtomic(Bad, (short) 0, buffer, (short) 0, (short) Bad.length);
                apdu.setOutgoingAndSend((short) 0, (short) Bad.length);
            }
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
    
    private void echo(APDU apdu) {
		byte[] buffer = loadApdu(apdu);
		byte[] apduBuffer = apdu.getBuffer();

        Util.arrayCopyNonAtomic(buffer, apdu.getOffsetCdata(), apduBuffer, (short) 0, (short) (extApduSize - apdu.getOffsetCdata()));
        apdu.setOutgoingAndSend((short) 0, (short) (extApduSize - apdu.getOffsetCdata()));
    }

    private boolean verifySignaturePrehashed() {
        setOIDCPublicKey();
        Signature sigObj = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        sigObj.init(OIDC_PUBLIC_KEY, Signature.MODE_VERIFY);

        return sigObj.verifyPreComputedHash(
            precomputedDigest,
            (short) 0,
            (short) precomputedDigest.length,
            derEncodedSignature,
            (short) 0,
            (short) derEncodedSignature.length
        );
    }

    private boolean verifySignature(byte[] message, short msgOffset, short msgLen, byte[] signature, short sigOffset, short sigLen) 
    {
        setOIDCPublicKey();
        Signature sigObj = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
        sigObj.init(OIDC_PUBLIC_KEY, Signature.MODE_VERIFY);

        return sigObj.verify(
            message, msgOffset, msgLen,
            signature, sigOffset, sigLen
        );
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

    private boolean verifyJWT(byte[] token) {
        // the Signing input cannot be prehashed, but has to be hashed on the card
        // thus the card has to get the token in base64 URL safe and
        // and it cannot receive the decoded value cause it would have to then trust the
        // contents anyway
        return false;
    }

    private void base64UrlsafeDecode(byte[] encoded, short length) {
        // 
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


    private static final byte PADDING = '=';

    public void findValue(APDU apdu) {
		byte[] buffer = loadApdu(apdu);
		byte[] apduBuffer = apdu.getBuffer();

        short firstDot = indexOf(buffer, (short) 0,  extApduSize, (byte) '.');
        System.out.println(String.format("firstDot: %d", firstDot));
        short secondDot = indexOf(buffer, (short) (firstDot + 1), extApduSize, (byte) '.');
        System.out.println(String.format("secondDot: %d", secondDot));

        short nDecoded = 0;
        nDecoded = base64UrlSafeDecoder.decodeBase64Urlsafe(
            buffer,
            (short) (firstDot + 1),
            // (short) (secondDot - firstDot),
            (short) (secondDot - (firstDot + 1)),
            // (short) (128),
            procBuffer,
            (short) 0
        );

        short fieldLength = getStringValueFor(procBuffer, (short) 0, nDecoded, AUD_FIELD_NAME, apduBuffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, fieldLength);
    }

    public void deriveSalt(APDU apdu) {
		byte[] buffer = loadApdu(apdu);
		byte[] apduBuffer = apdu.getBuffer();

        short firstDot = indexOf(buffer, (short) 0,  extApduSize, (byte) '.');
        System.out.println(String.format("firstDot: %d", firstDot));
        short secondDot = indexOf(buffer, (short) (firstDot + 1), extApduSize, (byte) '.');
        System.out.println(String.format("secondDot: %d", secondDot));

        short nDecoded = 0;
        nDecoded = decodeBase64Urlsafe(
            buffer,
            (short) (firstDot + 1),
            // (short) (secondDot - firstDot),
            (short) (secondDot - (firstDot + 1)),
            // (short) (128),
            procBuffer,
            (short) 0
        );

        short hashSize = deriveHashSecret(procBuffer, nDecoded, apdu);
        // add signature verification

        // short fieldLength = getStringValueFor(procBuffer, (short) 0, nDecoded, NAME_FIELD_NAME, apduBuffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, hashSize);
    }


    public short getStringValueFor(byte[] input, short inputOffset, short inputLen, byte[] key, byte[] output, short outputLen) {

        // NOTE assumes doublequotes and appearing in pairs
        byte DOUBLEQUOTE = '"';
        // byte COMMA = ',';
        // byte COLON = ':';
        

        short start = indexOf(input, inputOffset, inputLen, DOUBLEQUOTE);
        short end = indexOf(input, (short) (start + 1), inputLen, DOUBLEQUOTE);
        while ( start != -1) {
            // System.out.println(String.format("start: %d", start));
            // System.out.println(String.format("end: %d", end));
            // for (short i = (short) (start + 1); i < end; i++ ) {
            //     System.out.print(String.format("%c", input[i]));
            // }
            // byte[] slice = Arrays.copyOfRange(input, start, end);
            // System.out.println();
            if ( Util.arrayCompare(input, (short) (start + 1), key, (short) 0, (short) (key.length)) == (byte) 0 ) {
                // Look up the value
                start = indexOf(input, (short) (end + 1), inputLen, DOUBLEQUOTE);
                // System.out.println(start);
                end = indexOf(input, (short) (start + 1), inputLen, DOUBLEQUOTE);
                // System.out.println(end);
                for (short i = (short) (start + 1); i < end; i++ ) {
                    System.out.print(String.format("%c", input[i]));
                }
                // Util.arrayCopyNonAtomic(input, (short) (start + 1), output, (short) 0, (short) (end - start));
                Util.arrayCopyNonAtomic(input, (short) (start + 1), output, (short) 0, (short) (end - start - 1));
                return (short) (end - start - 1);
            }
            start = indexOf(input, (short) (end + 1), inputLen, DOUBLEQUOTE);
            end = indexOf(input, (short) (start + 1), inputLen, DOUBLEQUOTE);
        }
        return -1;
    }

    public void decode(APDU apdu) {
        // byte[5] APDU header | byte[X] Token header | . | byte[Y] Token body | . | byte[Z] Token signature
		byte[] buffer = loadApdu(apdu);
		byte[] apduBuffer = apdu.getBuffer();
        // byte[] token = (byte[]) (buffer + apdu.getOffsetCdata());
        // short tokenSize = extApduSize - apdu.getOffsetCdata();

        short firstDot = indexOf(buffer, (short) 0,  extApduSize, (byte) '.');
        System.out.println(String.format("firstDot: %d", firstDot));
        short secondDot = indexOf(buffer, (short) (firstDot + 1), extApduSize, (byte) '.');
        System.out.println(String.format("secondDot: %d", secondDot));

        // System.out.println(buffer);
        // byte[] slice = Arrays.copyOfRange(buffer, firstDot, secondDot);
        // short nDecoded = base64UrlSafeDecoder.decodeBase64Urlsafe(buffer, (short) 0,  firstDot, procBuffer, (short) 0);

        short nDecoded = base64UrlSafeDecoder.decodeBase64Urlsafe(
            buffer,
            (short) (secondDot + 1),
            (short) (extApduSize - secondDot + 1),
            procBuffer,
            (short) 0
        );
        // System.out.println(procBuffer);
        // optimize copying the signature
        Util.arrayCopyNonAtomic(procBuffer, (short) 0, derSignature, (short) 5, (short) 32); // set r-value
        Util.arrayCopyNonAtomic(procBuffer, (short) 32, derSignature, (short) 39 /* 4 + 32 + 3 */, (short) 32); // set s-value
        System.out.println();

        // // hardcode DER signature values
        // derSignature[0] = (byte) 0x30;
        // derSignature[1] = (byte) 0x45;
        // derSignature[2] = (byte) 0x02;
        // derSignature[3] = (byte) 0x20;
        // // r-value
        // derSignature[36] = (byte) 0x02;
        // derSignature[37] = (byte) 0x21;
        // derSignature[38] = (byte) 0x00;

        // 30
        // 45
        // 02
        // 21
        // 00
        // 9afd8998887696ed1472986fd67e86a27e89d80c2833b1309038da46a22dfc52
        // 0220
        // 77498396412814cea7ab9d8a2aef8f5cdac9bd1e9004686cf5ffca21575f63f3
        // hardcode DER signature values
        derSignature[0] = (byte) 0x30;
        derSignature[1] = (byte) 0x45;
        derSignature[2] = (byte) 0x02;
        derSignature[3] = (byte) 0x21;
        derSignature[4] = (byte) 0x00;
        // r-value
        derSignature[37] = (byte) 0x02;
        derSignature[38] = (byte) 0x20;
        // s-value

        if ( verifySignature(buffer, (short) 0, secondDot, derSignature, (short) 0, (short) 71) ) {
            Util.arrayCopyNonAtomic(Good, (short) 0, apduBuffer, (short) 0, (short) Good.length);
            apdu.setOutgoingAndSend((short) 0, (short) Good.length);
        } else {
            Util.arrayCopyNonAtomic(Bad, (short) 0, apduBuffer, (short) 0, (short) Bad.length);
            apdu.setOutgoingAndSend((short) 0, (short) Bad.length);
        }

        // nDecoded = base64UrlSafeDecoder.decodeBase64Urlsafe(
        //     buffer,
        //     (short) 0,
        //     (short) (firstDot + 1),
        //     procBuffer,
        //     (short) 0
        // );

        // short len = 124;
        // nDecoded = base64UrlSafeDecoder.decodeBase64Urlsafe(
        //     buffer,
        //     (short) (firstDot + 1),
        //     // (short) (secondDot - firstDot + 1),
        //     (short) (len),
        //     procBuffer,
        //     (short) 0
        // );

        // FIXME the size of the decoded token will differ
        // apdu.setOutgoingAndSend((short) 0,  (short) (len / 4 * 3));
    }

    public short indexOf(byte[] buffer, short offset, short bufferSize, byte token) {
        for (short i = offset; i < bufferSize; i++) {
            if ( buffer[i] == token ) {
                return i;
            }
        }
        return -1;
    }

    // public void 

    // FIXME return an error if problem?
    // FIXME there is quite likely some of by one error when decoding values 

    private byte[] intToBytes(int value, byte[] input) {
        input[0] = (byte) (value >> 16 & 0xFF);
        input[1] = (byte) (value >>  8 & 0xFF);
        input[2] = (byte) (value >>  0 & 0xFF);

        return input;
    }

    private byte[] loadApdu(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        short recvLen = apdu.setIncomingAndReceive(); // + apdu.getOffsetCdata());
        if (apdu.getOffsetCdata() == ISO7816.OFFSET_CDATA) {
            extApduSize = recvLen;
            System.out.println(String.format("extApduSize: %d", extApduSize));
            Util.arrayCopyNonAtomic(apduBuffer, (short) ISO7816.OFFSET_CDATA, extApduBuffer, (short) 0, recvLen);
            return extApduBuffer;
        }

        Util.arrayCopyNonAtomic(apduBuffer, apdu.getOffsetCdata(), extApduBuffer, (short) 0, recvLen);
        short written = recvLen;
        recvLen = apdu.receiveBytes((short) 0);
        while (recvLen > 0) {
            Util.arrayCopyNonAtomic(apduBuffer, (short) 0, extApduBuffer, written, recvLen);
            written += recvLen;
            recvLen = apdu.receiveBytes((short) 0);
        }
        extApduSize = written;
        System.out.println(String.format("extApduSize: %d", extApduSize));
        return extApduBuffer;
    }

}
