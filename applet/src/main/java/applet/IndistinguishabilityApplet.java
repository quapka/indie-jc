package applet;

import javacard.framework.Util;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.SystemException;
import javacard.framework.TransactionException;
import javacard.framework.CardRuntimeException;
import javacard.framework.PINException;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacardx.crypto.Cipher;
import javacardx.apdu.ExtendedLength;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.Signature;
import javacard.security.KeyBuilder;
import javacard.security.ECPublicKey;
import javacard.security.ECPrivateKey;
import javacard.security.MessageDigest;
import javacard.security.KeyAgreement;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.RandomData;

import applet.Consts;

import applet.jcmathlib.OperationSupport;
import applet.jcmathlib.ResourceManager;
import applet.jcmathlib.SecP256r1;
// import applet.Utils;

// FIXME change all (short) 0 to ZERO final 0x00 byte value?
public class IndistinguishabilityApplet extends Applet implements ExtendedLength
{
    public final static short CARD_TYPE = CardType.CARD_TYPE;

    public static ResourceManager rm;
    public static DiscreteLogEquality dleq;
    KeyAgreement ecdh = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_KDF, false);
    MessageDigest hasher = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
    Signature sigObj = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);
    public static RandomData rng;

    private static byte[] currentEpoch = new byte[64];

    private Musig2 musig2;

    // Compiling the CAP with ./gradlew buildJavaCard fails due to the symbol
    // Cipher.ALG_AES_CTR not being found. The constants are defined in:
    // https://docs.oracle.com/en/java/javacard/3.2/jcapi/api_classic/constant-values.html#javacardx.crypto.Cipher.ALG_AES_CBC_PKCS5
    // However, the target card JCOP4 should support this algorithm, thus we
    // set the constant ourselves, see:
    // https://github.com/crocs-muni/jcalgtest_results/blob/main/javacard/Profiles/results/NXP_JCOP4_J3R180_SecID_Feitian_ALGSUPPORT__3b_d5_18_ff_81_91_fe_1f_c3_80_73_c8_21_10_0a_(provided_by_PetrS).csv#L81
    public static final byte Cipher_ALG_AES_CTR = -16;
    public static final short uncompressPubKeySize = 65;

	private static final byte[] helloWorld = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!'};
	public static final byte[] Good = {'G', 'O', 'O', 'D'};
	public static final byte[] Bad = {'B', 'A', 'D'};
	private static final byte[] None = {'N', 'o', 'n', 'e'};

    private byte[] salt = new byte[32];
    // at least shal handle 65 bytes of uncompressed points
    private byte[] tmp = new byte[2048];
    // TODO is the maximal ECDSA DER encoded signature 72 bytes?
	private byte[] derSignature = new byte[72];

	private static final byte[] NONCE_FIELD_NAME = {'n', 'o', 'n', 'c', 'e'};
	private static final byte[] AUD_FIELD_NAME = {'a', 'u', 'd'};
	private static final byte[] NAME_FIELD_NAME = {'n', 'a', 'm', 'e'};

    public static byte nParties;
    public static byte threshold;
    // TODO AESKey or only Key
    private static AESKey aesCtrKey;
    private static Cipher aesCtr;

	private static final byte[] HASH_SECRET_DOMAIN_SEPARATOR = {'S', 'a', 'l', 't', ' ', 's', 'e', 'r', 'v', 'i', 'c', 'e'};

    // indie-service HASH_SALT_SECRET
    // FIXME generate inside the card as part of the setup
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

    private boolean initialized = false;

    private KeyPair ecKeyPair;
    private ECPrivateKey privDVRFKey;
    private ECPublicKey pubDVRFKey;

    private ECPublicKey OIDC_PUBLIC_KEY = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false);

    private Base64UrlSafeDecoder base64UrlSafeDecoder;

	public static void install(byte[] bArray, short bOffset, byte bLength)
	{
		new IndistinguishabilityApplet(bArray, bOffset, bLength);
	}

	public IndistinguishabilityApplet(byte[] bArray, short bOffset, byte bLength) {
        OperationSupport.getInstance().setCard(CARD_TYPE);
        if (!OperationSupport.getInstance().DEFERRED_INITIALIZATION) {
            initialize();
        }
		register();
	}

    public boolean select() {
        if (initialized) {
            DiscreteLogEquality.curve.updateAfterReset();
        }
        return true;
    }

    // FIXME implement, deselect() and possibly other Applet.* methods?
	public void process(APDU apdu)
	{
        if ( selectingApplet() ) {
            return;
        }

        if ( !initialized ) {
            initialize();
        }

        byte[] buffer = apdu.getBuffer();
        byte cla = buffer[ISO7816.OFFSET_CLA];
        byte ins = buffer[ISO7816.OFFSET_INS];
        byte p1 = buffer[ISO7816.OFFSET_P1];
        byte p2 = buffer[ISO7816.OFFSET_P2];

        try {
            if ( cla == Consts.CLA.DEBUG ) {
                switch (ins) {
                    case Consts.INS.GOOD:
                        sendGood(apdu);
                        break;
                    case Consts.INS.BAD:
                        sendBad(apdu);
                        break;
                    case Consts.INS.COMPUTE_MOD_MULT:
                        dleq.calculateModMult(apdu);
                        break;
                    case Consts.INS.AES_CTR_DECRYPT:
                        sendDecrypted(apdu);
                        break;
                    case Consts.INS.VERIFY_COMMITMENT:
                        verifyCommitment(apdu);
                        break;
                    case Consts.INS.VERIFY_JWT:
                        verifyJWT(apdu);
                        break;
                    case Consts.INS.DERIVE_SALT:
                        deriveSalt(apdu);
                        break;
                    case Consts.INS.DECODE_JWT:
                        decodeJwtBody(apdu);
                        break;
                    case Consts.INS.VERIFY_ENCRYPTED_JWT:
                        verifyEncryptedJwt(apdu);
                        break;
                    case Consts.INS.VERIFY_ENCRYPTED_JWT_AND_COMMITMENT:
                        verifyEncryptedJwtAndCommitment(apdu);
                        break;
                    case Consts.INS.IS_INITIALIZED:
                        getInitialized(apdu);
                        break;
                }
            } else if ( cla == Consts.CLA.INDIE ) {
                switch (ins) {
                    case Consts.INS.SET_OIDC_PUBKEY:
                        setOIDCPublicKey(apdu);
                        break;
                    case Consts.INS.GET_OIDC_PUBKEY:
                        getOIDCPublicKey(apdu);
                        break;
                    case Consts.INS.SETUP:
                        setup(apdu);
                        break;
                    case Consts.INS.GET_SETUP:
                        getSetup(apdu);
                        break;
                    case Consts.INS.KEY_GEN:
                        generateDVRFKeypair(apdu);
                        break;
                    case Consts.INS.GET_VERIFICATION_PUBKEY:
                        System.out.println("About to getDerivationPubkey");
                        getDerivationPubkey(apdu);
                        break;
                    case Consts.INS.GET_EXAMPLE_PROOF:
                        System.out.println("About to computeDleq");
                        computeDleq(apdu);
                        break;
                    case Consts.INS.GET_CURRENT_EPOCH:
                        getCurrentEpoch(apdu);
                        break;
                    case Consts.INS.GENERATE_KEY_MUSIG2:
                        generateKeys(apdu);
                        break;
                    default:
                        break;
                }
            } else {
                ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
            }
        } catch (ISOException e) {
            throw e; // Our exception from code, just re-emit
        } catch (ArrayIndexOutOfBoundsException e) {
            ISOException.throwIt(Consts.SW_ArrayIndexOutOfBoundsException);
        } catch (ArithmeticException e) {
            ISOException.throwIt(Consts.SW_ArithmeticException);
        } catch (ArrayStoreException e) {
            ISOException.throwIt(Consts.SW_ArrayStoreException);
        } catch (NullPointerException e) {
            ISOException.throwIt(Consts.SW_NullPointerException);
        } catch (NegativeArraySizeException e) {
            ISOException.throwIt(Consts.SW_NegativeArraySizeException);
        } catch (CryptoException e) {
            ISOException.throwIt((short) (Consts.SW_CryptoException_prefix | e.getReason()));
        } catch (SystemException e) {
            ISOException.throwIt((short) (Consts.SW_SystemException_prefix | e.getReason()));
        } catch (PINException e) {
            ISOException.throwIt((short) (Consts.SW_PINException_prefix | e.getReason()));
        } catch (TransactionException e) {
            ISOException.throwIt((short) (Consts.SW_TransactionException_prefix | e.getReason()));
        } catch (CardRuntimeException e) {
            ISOException.throwIt((short) (Consts.SW_CardRuntimeException_prefix | e.getReason()));
        } catch (Exception e) {
            ISOException.throwIt(Consts.SW_Exception);
        }

	}

    private void initialize() {
        if ( initialized ) {
            return;
        }
        rm = new ResourceManager((short) 256);
        // rm = new ResourceManager((short) 256, (short) 2056);
        rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        dleq = new DiscreteLogEquality();
        musig2 = new Musig2(DiscreteLogEquality.curve, rm);
        if ( CARD_TYPE == OperationSupport.JCOP4_P71 ) {
            rm.fixModSqMod(DiscreteLogEquality.curve.rBN);
        }
        aesCtr = Cipher.getInstance(Cipher_ALG_AES_CTR, false);
        // change to TYPE_AES_TRANSIENT_RESET
        aesCtrKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);


        // TODO Use the following init instead?
        // if ( !DiscreteLogEquality.initialized ) {
        //     dleq.initialize();
        // }
        // if ( !dleq.initialized ) {
        //     dleq.initialize();
        // }

        base64UrlSafeDecoder = new Base64UrlSafeDecoder();

        initialized = true;
    }

    private void setup(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        nParties = apduBuffer[ISO7816.OFFSET_P1];
        threshold = apduBuffer[ISO7816.OFFSET_P2];
    }

    private void getSetup(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        apduBuffer[0] = nParties;
        apduBuffer[1] = threshold;

        apdu.setOutgoingAndSend((short) 0, (short) 2);
    }

    // private void decryptAesPayload(APDU apdu) {
    // }
    public void generateKeys (APDU apdu) {
        byte[] apduBuffer = loadApdu(apdu);
        musig2.individualPubkey(apduBuffer, apdu.getOffsetCdata());

        ISOException.throwIt(ISO7816.SW_NO_ERROR);
    }

    private void sendDecrypted(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        short _bytesRead = apdu.setIncomingAndReceive();
        byte ctxtLen = apduBuffer[ISO7816.OFFSET_P1];

        short ptxtLen = aesCtrDecryptInner(apduBuffer, ISO7816.OFFSET_CDATA, ctxtLen, tmp, (short) 0);

		Util.arrayCopyNonAtomic(tmp, (short) 0, apduBuffer, (short) 0, ptxtLen);
		apdu.setOutgoingAndSend((short) 0, ptxtLen);
    }

    private void verifyEncryptedJwtAndCommitment(APDU apdu) {
        byte[] buffer = loadApdu(apdu);
        byte[] apduBuffer = apdu.getBuffer();
        // the sizes are in bytes
        short aesCtrNonceSize = 16;
        short uncompressedECPointSize = 65;
        short zkNonceSize = 32;

        short ctxtLen = (short) (extApduSize - aesCtrNonceSize - uncompressedECPointSize - zkNonceSize);

        short ptxtLen = aesCtrDecryptInner(buffer, (short) 0, ctxtLen, tmp, (short) 0);

        boolean jwtIsvalid = validJwt(tmp, (short) 0, ptxtLen);
        if ( !jwtIsvalid ) {
            Util.arrayCopyNonAtomic(Bad, (short) 0, apduBuffer, (short) 0, (short) Bad.length);
            apdu.setOutgoingAndSend((short) 0, (short) Bad.length);
            return;
        }

        // FIXME add domain separator?
        hasher.reset();
        // zkNonce
        hasher.update(buffer, (short) (extApduSize - zkNonceSize), zkNonceSize);
        // clientPubpoint
        hasher.doFinal(buffer, (short) 0, uncompressedECPointSize, procBuffer, (short) 0);

        short firstDot = indexOf(tmp, (short) 0,  ptxtLen, (byte) '.');
        short secondDot = indexOf(tmp, (short) (firstDot + 1), ptxtLen, (byte) '.');
        short nDecoded = base64UrlSafeDecoder.decodeBase64Urlsafe(
            tmp,
            (short) (firstDot + 1),
            (short) (secondDot - (firstDot + 1)),
            tmp,
            (short) 0
        );

        // NOTE: As part of some attack the nonce could be empty. Therefore,
        // the size comparison needs to be hardcoded and not inferred from the
        // value itself.
        short valueLen = getValueFor(tmp, (short) 0, nDecoded, NONCE_FIELD_NAME, procBuffer, uncompressedECPointSize);

        Utils.fromUppercaseHex(procBuffer, uncompressedECPointSize, (short) 64, procBuffer,  uncompressedECPointSize);

        boolean pubkeyIsValid = Util.arrayCompare(procBuffer, (short) 0, procBuffer, uncompressedECPointSize, (short) 32) == 0;

        if ( jwtIsvalid && pubkeyIsValid) {
            // derive salt
            short hashSize = deriveHashSecret(tmp, nDecoded, buffer, (short) (uncompressedECPointSize + aesCtrNonceSize));
            // and encrypt it
            ctxtLen = aesCtrEncryptInner(buffer, (short) 0, hashSize, apduBuffer, (short) 0);
            apdu.setOutgoingAndSend((short) 0, ctxtLen);
        } else {
            Util.arrayCopyNonAtomic(Bad, (short) 0, apduBuffer, (short) 0, (short) Bad.length);
            apdu.setOutgoingAndSend((short) 0, (short) Bad.length);
        }
    }

    private void verifyEncryptedJwt(APDU apdu) {
        byte[] buffer = loadApdu(apdu);
        byte[] apduBuffer = apdu.getBuffer();
        short ctxtLen = (short) (extApduSize - 16 - 65);

        short ptxtLen = aesCtrDecryptInner(buffer, (short) 0, ctxtLen, tmp, (short) 0);
        System.out.println(ptxtLen);

        System.out.println("In-card token");
        for (short i = 0; i < ptxtLen; i++) {
            System.out.print(String.format("%02X", tmp[i]));
        }
        System.out.println();

        if ( validJwt(tmp, (short) 0, ptxtLen) ) {
            Util.arrayCopyNonAtomic(Good, (short) 0, apduBuffer, (short) 0, (short) Good.length);
            apdu.setOutgoingAndSend((short) 0, (short) Good.length);
        } else {
            Util.arrayCopyNonAtomic(Bad, (short) 0, apduBuffer, (short) 0, (short) Bad.length);
            apdu.setOutgoingAndSend((short) 0, (short) Bad.length);
        }
    }

    private short aesCtrDecryptInner(byte[] buffer, short offset, short ctxtLen, byte[] out, short outOff) {
        short pointLen = 65;
        byte nonceByteSize = 16;

        // FIXME use dedicated key-identity card?
        ecdh.init(privDVRFKey);
        ecdh.generateSecret(buffer, offset, pointLen, tmp, (short) 0);
        aesCtrKey.setKey(tmp, (short) 0);
        aesCtr.init(aesCtrKey, Cipher.MODE_DECRYPT, buffer, (short) (offset + pointLen), (short) nonceByteSize);

        return aesCtr.doFinal(buffer, (short) (offset + nonceByteSize + pointLen), ctxtLen, out, outOff);
    }

    // Encrypt and decrypt is almost the same, except the mode, refactor into a single function?
    private short aesCtrEncryptInner(byte[] buffer, short offset, short ptxtLen, byte[] out, short outOff) {
        short pointLen = 65;
        byte nonceByteSize = 16;
        // generate new nonce directly to the output
        rng.generateData(out, (short) 0, nonceByteSize);

        System.out.println("nonce");
        for (short i = 0; i < nonceByteSize; i++) {
            System.out.print(String.format("%02X", out[i]));
        }
        System.out.println();

        // FIXME use dedicated key-identity card?
        ecdh.init(privDVRFKey);
        ecdh.generateSecret(buffer, offset, pointLen, tmp, (short) 0);
        aesCtrKey.setKey(tmp, (short) 0);
        aesCtr.init(aesCtrKey, Cipher.MODE_ENCRYPT, out, (short) 0, (short) nonceByteSize);

        return (short) (nonceByteSize + aesCtr.doFinal(buffer, (short) (offset + nonceByteSize + pointLen), ptxtLen, out, nonceByteSize));
    }

    private void verifyCommitment(APDU apdu) {
        // FIXME What is the expected NONCE encoding? Hexadecimal or base64 encoded?
		byte[] apduBuffer = apdu.getBuffer();
        short _bytesRead = apdu.setIncomingAndReceive();
        byte zkNonceLength = apduBuffer[ISO7816.OFFSET_P1];
        byte pubKeyLength = apduBuffer[ISO7816.OFFSET_P2];


        hasher.reset();
        hasher.update(apduBuffer, (short) ISO7816.OFFSET_CDATA, zkNonceLength);
        hasher.doFinal(apduBuffer, (short) (ISO7816.OFFSET_CDATA + zkNonceLength), pubKeyLength, tmp, (short) 0);

        if (Util.arrayCompare(apduBuffer, (short) (ISO7816.OFFSET_CDATA + zkNonceLength + pubKeyLength), tmp, (short) 0, (short) hasher.getLength()) == 0) {
            Util.arrayCopyNonAtomic(Good, (short) 0, apduBuffer, (short) 0, (short) Good.length);
            apdu.setOutgoingAndSend((short) 0, (short) Good.length);
        } else {
            Util.arrayCopyNonAtomic(Bad, (short) 0, apduBuffer, (short) 0, (short) Bad.length);
            apdu.setOutgoingAndSend((short) 0, (short) Bad.length);
        }
    }

    private void setOIDCPublicKey(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short _bytesRead = apdu.setIncomingAndReceive();
        // FIXME move to constructor KeyBuilder
        short offset = 0;
        OIDC_PUBLIC_KEY.setFieldFP(SecP256r1.p, offset, (short) SecP256r1.p.length);
        OIDC_PUBLIC_KEY.setA(SecP256r1.a, offset, (short) SecP256r1.a.length);
        OIDC_PUBLIC_KEY.setB(SecP256r1.b, offset, (short) SecP256r1.b.length);
        OIDC_PUBLIC_KEY.setG(SecP256r1.G, offset, (short) SecP256r1.G.length);
        OIDC_PUBLIC_KEY.setR(SecP256r1.r, offset, (short) SecP256r1.r.length);
        OIDC_PUBLIC_KEY.setK(SecP256r1.k);
        OIDC_PUBLIC_KEY.setW(buffer, (short) ISO7816.OFFSET_CDATA, uncompressPubKeySize);

        getOIDCPublicKey(apdu);
    }

    private void getOIDCPublicKey(APDU apdu) {
        short keySize = OIDC_PUBLIC_KEY.getW(apdu.getBuffer(), (short) 0);
        apdu.setOutgoingAndSend((short) 0, keySize);
    }

    public short deriveHashSecret(byte[] body, short bodySize, byte[] out) {
        // default to 0 output offset
        return  deriveHashSecret(body, bodySize, out, (short) 0);
    }

    public short deriveHashSecret(byte[] body, short bodySize, byte[] out, short outOffset) {
        hasher.reset();
        hasher.update(HASH_SECRET_DOMAIN_SEPARATOR, (short) 0, (short) HASH_SECRET_DOMAIN_SEPARATOR.length);

        short valueLen = getValueFor(body, (short) 0, bodySize, AUD_FIELD_NAME, tmp, (short) 0);
        hasher.update(tmp, (short) 0, valueLen);

        valueLen = getValueFor(body, (short) 0, bodySize, NAME_FIELD_NAME, tmp, (short) 0);
        hasher.update(tmp, (short) 0, valueLen);

        hasher.doFinal(HASH_SALT_SECRET, (short) 0, (short) HASH_SALT_SECRET.length, out, outOffset);
        return hasher.getLength();

    }

    /**
     * Generates new ECC Keypair, stores it in `privDVRFKey` and `pubDVRFKey`
     * and returns the public part (encoded as 65B) via APDU
     */
    private void generateDVRFKeypair(APDU apdu) {

        privDVRFKey = (ECPrivateKey) KeyBuilder.buildKey(
            KeyBuilder.TYPE_EC_FP_PRIVATE,
            KeyBuilder.LENGTH_EC_FP_256,
            false
        );
        pubDVRFKey = (ECPublicKey) KeyBuilder.buildKey(
            KeyBuilder.TYPE_EC_FP_PUBLIC,
            KeyBuilder.LENGTH_EC_FP_256,
            false
        );

         try {
            if ( pubDVRFKey == null) {
                ecKeyPair.genKeyPair();
            }
        } catch (Exception e) {
        } // do intentionally nothing

        short offset = 0;

        pubDVRFKey.setFieldFP(SecP256r1.p, offset, (short) SecP256r1.p.length);
        pubDVRFKey.setA(SecP256r1.a, offset, (short) SecP256r1.a.length);
        pubDVRFKey.setB(SecP256r1.b, offset, (short) SecP256r1.b.length);
        pubDVRFKey.setG(SecP256r1.G, offset, (short) SecP256r1.G.length);
        pubDVRFKey.setR(SecP256r1.r, offset, (short) SecP256r1.r.length);
        pubDVRFKey.setK(SecP256r1.k);

        privDVRFKey.setFieldFP(SecP256r1.p, offset, (short) SecP256r1.p.length);
        privDVRFKey.setA(SecP256r1.a, offset, (short) SecP256r1.a.length);
        privDVRFKey.setB(SecP256r1.b, offset, (short) SecP256r1.b.length);
        privDVRFKey.setG(SecP256r1.G, offset, (short) SecP256r1.G.length);
        privDVRFKey.setR(SecP256r1.r, offset, (short) SecP256r1.r.length);
        privDVRFKey.setK(SecP256r1.k);

        ecKeyPair = new KeyPair(pubDVRFKey, privDVRFKey);

        ecKeyPair.genKeyPair();

        byte[] apduBuffer = apdu.getBuffer();
        short keySize = pubDVRFKey.getW(apduBuffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, keySize);
    }

    
    private void verifyJWT(APDU apdu) {
		byte[] buffer = loadApdu(apdu);
		byte[] apduBuffer = apdu.getBuffer();

        System.out.println("Plaintex JWT verify");
        for (short i = 0; i < extApduSize; i++) {
            System.out.print(String.format("%02X", buffer[i]));
        }
        System.out.println();


        if (validJwt(buffer, (short) 0,  extApduSize)) {
            Util.arrayCopyNonAtomic(Good, (short) 0, apduBuffer, (short) 0, (short) Good.length);
            apdu.setOutgoingAndSend((short) 0, (short) Good.length);
        } else {
            Util.arrayCopyNonAtomic(Bad, (short) 0, apduBuffer, (short) 0, (short) Bad.length);
            apdu.setOutgoingAndSend((short) 0, (short) Bad.length);
        }
    }

    private boolean validJwt(byte[] buffer, short offset, short length) {
        // The expected JWT format in the buffer is
        // {header}.{body}.{signature}
        short firstDot = indexOf(buffer, offset,  length, (byte) '.');
        System.out.println(String.format("firstDot: %d", firstDot));
        short secondDot = indexOf(buffer, (short) (firstDot + 1), length, (byte) '.');
        System.out.println(String.format("secondDot: %d", secondDot));

        short nDecoded = base64UrlSafeDecoder.decodeBase64Urlsafe(
            buffer,
            (short) (secondDot + 1),
            (short) (length - (secondDot + 1)),
            procBuffer,
            (short) 0
        );

        System.out.println("Base64 signature");
        for (short i = (short) (secondDot + 1); i < length; i++) {
            System.out.print(String.format("%02X", buffer[i]));
        }
        System.out.println();

        System.out.println("Decoded signature:");
        for (short i = 0; i < nDecoded; i++) {
            System.out.print(String.format("%02X", procBuffer[i]));
        }
        System.out.println();

        short sigLen = Utils.derEncodeRawEcdsaSignature(procBuffer, derSignature);
        return verifySignature(buffer, (short) 0, secondDot, derSignature, (short) 0, sigLen);
    }

    private boolean verifySignature(byte[] message, short msgOffset, short msgLen, byte[] signature, short sigOffset, short sigLen) 
    {
        sigObj.init(OIDC_PUBLIC_KEY, Signature.MODE_VERIFY);

        return sigObj.verify(
            message, msgOffset, msgLen,
            signature, sigOffset, sigLen
        );
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

	private void getInitialized(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
        if ( initialized ) {
            Util.setShort(buffer, (short) 0, (short) 0xffff);
            apdu.setOutgoingAndSend((short) 0, (short) 2);
        } else {
            Util.setShort(buffer, (short) 0, (short) 0x0000);
            apdu.setOutgoingAndSend((short) 0, (short) 2);
        }
	}

    // private boolean verifyJWT(byte[] token) {
    //     // the Signing input cannot be prehashed, but has to be hashed on the card
    //     // thus the card has to get the token in base64 URL safe and
    //     // and it cannot receive the decoded value cause it would have to then trust the
    //     // contents anyway
    //     return false;
    // }

    private void base64UrlsafeDecode(byte[] encoded, short length) {
        // 
    }

    private static final byte PADDING = '=';

    public void decodeJwtBody(APDU apdu) {
		byte[] buffer = loadApdu(apdu);

        short firstDot = indexOf(buffer, (short) 0,  extApduSize, (byte) '.');
        short secondDot = indexOf(buffer, (short) (firstDot + 1), extApduSize, (byte) '.');

        short nDecoded = 0;
        nDecoded = base64UrlSafeDecoder.decodeBase64Urlsafe(
            buffer,
            (short) (firstDot + 1),
            (short) (secondDot - (firstDot + 1)),
            buffer,
            (short) 0
        );

        apdu.setOutgoingAndSend((short) 0, nDecoded);
    }

    public void deriveSalt(APDU apdu) {
		byte[] buffer = loadApdu(apdu);
		byte[] apduBuffer = apdu.getBuffer();

        short firstDot = indexOf(buffer, (short) 0,  extApduSize, (byte) '.');
        System.out.println(String.format("firstDot: %d", firstDot));
        short secondDot = indexOf(buffer, (short) (firstDot + 1), extApduSize, (byte) '.');
        System.out.println(String.format("secondDot: %d", secondDot));

        short nDecoded = 0;
        // add signature verification
        nDecoded = base64UrlSafeDecoder.decodeBase64Urlsafe(
            buffer,
            (short) (secondDot + 1),
            (short) (extApduSize - (secondDot + 1)),
            procBuffer,
            (short) 0
        );
        // encode signature
        short sigLen = Utils.derEncodeRawEcdsaSignature(procBuffer, derSignature);
        System.out.println(sigLen);
        for (short i = 0; i < sigLen; i++ ) {
            System.out.print(String.format("%02x", derSignature[i]));
        }
        System.out.println();
        if ( !verifySignature(buffer, (short) 0, secondDot, derSignature, (short) 0, sigLen) ) {
            Util.arrayCopyNonAtomic(Bad, (short) 0, apduBuffer, (short) 0, (short) Bad.length);
            // FIXME better output
            apdu.setOutgoingAndSend((short) 0, (short) Bad.length);
            return;
        }

        // if signature valid derive the salt
        nDecoded = base64UrlSafeDecoder.decodeBase64Urlsafe(
            buffer,
            (short) (firstDot + 1),
            (short) (secondDot - (firstDot + 1)),
            procBuffer,
            (short) 0
        );

        short hashSize = deriveHashSecret(procBuffer, nDecoded, apduBuffer);

        apdu.setOutgoingAndSend((short) 0, hashSize);
    }

    /**
     * Returns the verification public key for the salt derivation,
     * in particular, the discrete log of equality proof verification.
     */
    public void getDerivationPubkey(APDU apdu) {
		byte[] apduBuffer = apdu.getBuffer();

        ECPublicKey pubKey = DiscreteLogEquality.curve.disposablePub;
        short pubKeyLength = pubKey.getW(apduBuffer, (short) 0);

        apdu.setOutgoingAndSend((short) 0, pubKeyLength);
    }

    public void getCurrentEpoch(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		short length = (short) currentEpoch.length;
		Util.arrayCopyNonAtomic(currentEpoch, (short) 0, buffer, (short) 0, length);
		apdu.setOutgoingAndSend((short) 0, length);
    }

    public void computeDleq(APDU apdu) {
        System.out.println("computeDleq");
		byte[] buffer = loadApdu(apdu);
		byte[] apduBuffer = apdu.getBuffer();
        // FIXME for now the user provides already a point on the curve
        // however, in the TVRF the input is hashed-to-curve first
        // 1. get value from user
        // 2. hash it to curve
        for (short i = ISO7816.OFFSET_CDATA; i < ISO7816.OFFSET_CDATA + 65; i++) {
            System.out.print(String.format("%02x", apduBuffer[i]));
        }
        DiscreteLogEquality.userPoint.setW(apduBuffer, (short) (ISO7816.OFFSET_CDATA), (short) 65);
        System.out.println();
        // 3. multiply by secret
        DiscreteLogEquality.M.copy(DiscreteLogEquality.userPoint);
        DiscreteLogEquality.M.multiplication(DiscreteLogEquality.secret);
        // provide a proof of usage of the secret
        short proofLength = dleq.exampleProof(apduBuffer);
        short partialLength = DiscreteLogEquality.M.getW(apduBuffer, proofLength);

        apdu.setOutgoingAndSend((short) 0, (short) (proofLength + partialLength));
    }

    /**
     * Iterates through JSON `input`, starting at `inputOffset` until `key`
     * enclosed in double quotes is found. If the `key` is found its value is
     * copied to the `output` buffer.
     *
     *
     */
    public short getValueFor(byte[] input, short inputOffset, short inputLen, byte[] key, byte[] output, short outputOffset) {

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
            // FIXME do not copy, only give offset and length?
                Util.arrayCopyNonAtomic(input, (short) (start + 1), output, outputOffset, (short) (end - start - 1));
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
        for (short i = 0; i < derSignature.length; i++) {
            System.out.print(String.format("%02x", derSignature[i]));
        }
        System.out.println();

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

    /** 
     * Returns the index of a byte `token` in the `buffer` if found
     * and -1 otherwise.
     */
    public short indexOf(byte[] buffer, short offset, short bufferSize, byte token) {
        for (short i = offset; i < bufferSize; i++) {
            if ( buffer[i] == token ) {
                return i;
            }
        }
        return -1;
    }

    private byte[] loadApdu(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        short recvLen = apdu.setIncomingAndReceive(); // + apdu.getOffsetCdata());
        if (apdu.getOffsetCdata() == ISO7816.OFFSET_CDATA) {
            extApduSize = recvLen;
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
        return extApduBuffer;
    }

}
