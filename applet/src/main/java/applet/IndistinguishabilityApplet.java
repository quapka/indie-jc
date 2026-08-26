package applet;

import javacard.framework.Util;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.APDUException;
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
import applet.jcmathlib.ECCurve;
// import applet.Utils;

// FIXME change all (short) 0 to ZERO final 0x00 byte value?
public class IndistinguishabilityApplet extends Applet implements ExtendedLength
{
    public final static short CARD_TYPE = CardType.CARD_TYPE;

    public static ResourceManager rm;
    public static DiscreteLogEquality dleq;
    public static DistributedKeyGen dkg;
    public static HashToCurve h2c;
    KeyAgreement ecdh = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_KDF, false);
    MessageDigest hasher = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
    HashCustom customHasher;
    public static ECCurve curve;
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

    public static final byte[] Good = {'G', 'O', 'O', 'D'};
    public static final byte[] Bad = {'B', 'A', 'D'};

    // at least shal handle 65 bytes of uncompressed points
    private byte[] tmp = new byte[2048];
    // TODO is the maximal ECDSA DER encoded signature 72 bytes?
    private byte[] derSignature = new byte[72];

    private static final byte[] NONCE_FIELD_NAME = {'n', 'o', 'n', 'c', 'e'};
    private static final byte[] AUD_FIELD_NAME = {'a', 'u', 'd'};
    private static final byte[] NAME_FIELD_NAME = {'n', 'a', 'm', 'e'};
    private static final byte[] ISSUER_FIELD_NAME = {'i', 's', 's'};
    private static final byte[] SUBJECT_FIELD_NAME = {'s', 'u', 'b'};

    public byte nParties;
    public byte threshold;
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
    private static final short extResponseChunkSize = (short) 0xFF;

    private boolean initialized = false;

    private KeyPair ecKeyPair;
    private ECPrivateKey privDVRFKey;
    private ECPublicKey pubDVRFKey;

    private ECPublicKey OIDC_PUBLIC_KEY = (ECPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_EC_FP_PUBLIC, KeyBuilder.LENGTH_EC_FP_256, false);

    private Base64UrlSafeDecoder base64UrlSafeDecoder;

    public static void install(byte[] bArray, short bOffset, byte bLength)
    {
        // kudos to: https://stackoverflow.com/a/32841038/2377489
        short offset = bOffset;
        byte aidLength = bArray[bOffset];
        offset = (short) (offset + 1 + aidLength);

        short controlLength = (short)(bArray[offset] & (short) 0x00FF);
        offset = (short) (offset + 1 + controlLength);

        short dataLength = (short) (bArray[offset] & (short) 0x00FF);
        new IndistinguishabilityApplet(bArray, (short) (bOffset + 1 + aidLength + 1 + controlLength + 1), dataLength);
    }

    public IndistinguishabilityApplet(byte[] bArray, short bOffset, short bLength) {
        this.threshold = bArray[bOffset];
        this.nParties = bArray[(short) (bOffset + 1)];

        OperationSupport.getInstance().setCard(CARD_TYPE);
        if (!OperationSupport.getInstance().DEFERRED_INITIALIZATION) {
            initialize();
        }
        register();
    }

    public boolean select() {
        if (initialized) {
            // FIXME use only a single curve
            curve.updateAfterReset();
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
                    case Consts.INS.SETUP_TEST_DATA:
                        setUpTestData(apdu);
                        break;
                    case Consts.INS.GET_ALL_C_POINTS:
                        getAllCPoints(apdu);
                        break;
                    case Consts.INS.TEST_EXT_APDU_SIZE:
                        testExtApduBuf(apdu);
                        break;
                    case Consts.INS.EXT_APDU_ECHO:
                        echoExtApduBuffer(apdu);
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
                    case Consts.INS.GENERATE_NONCE_MUSIG2:
                        generateEpochNonce(apdu);
                        break;
                    case Consts.INS.GET_PUBLIC_NONCE_SHARE:
                        getPublicNonceShare(apdu);
                        break;
                    case Consts.INS.MUSIG2_SIGN:
                        musigSign(apdu);
                        break;
                    case Consts.INS.CREATE_PARTIAL_EPOCH:
                        createPartialEpoch(apdu);
                        break;
                    case Consts.INS.SET_MUSIG2_AGG_NONCE:
                        setPublicNonce(apdu);
                        break;
                    case Consts.INS.SET_MUSIG2_AGG_KEY:
                        setAggPubKey(apdu);
                        break;
                    case Consts.INS.KEY_GEN_DLEQ:
                        generateKeyDleq(apdu);
                        break;
                    case Consts.INS.SET_C_POINTS:
                        setCPoints(apdu);
                        break;
                    case Consts.INS.GET_C_POINTS:
                        getCPoints(apdu);
                        break;
                    case Consts.INS.GET_SHARES:
                        getShares(apdu);
                        break;
                    case Consts.INS.SET_SHARES:
                        setShares(apdu);
                        break;
                    case Consts.INS.COMPUTE_X_SHARE:
                        computeXShare(apdu);
                        break;
                    case Consts.INS.GET_A_POINTS:
                        getAPoints(apdu);
                        break;
                    case Consts.INS.SET_A_POINTS:
                        setAPoints(apdu);
                        break;
                    case Consts.INS.VERIFY_A_POINTS:
                        verifyAPoints(apdu);
                        break;
                    case Consts.INS.GET_DLEQ_KEY:
                        getDleqKey(apdu);
                        break;
                    case Consts.INS.DERIVE_DLEQ_SALT_SHARE:
                        deriveDleqSaltShare(apdu);
                        break;
                    case Consts.INS.DERIVE_SEED_SHARE:
                        deriveSeedShare(apdu);
                        break;
                    case Consts.INS.GET_PUBLIC_DLEQ_SHARE:
                        getDleqPublicShare(apdu);
                        break;
                    case Consts.INS.GENERATE_KEY_MUSIG2:
                        generateMusig2Key(apdu);
                        break;
                    case Consts.INS.COMPUTE_HASH_TO_CURVE:
                        getHashToCurve(apdu);
                        break;
                    case Consts.INS.GET_DLEQ_PARAMS:
                        getDleqParams(apdu);
                        break;
                    case Consts.INS.GET_COMMITMENTS:
                        getCommitments(apdu);
                        break;
                    case Consts.INS.GET_SECRET_SHARE:
                        getSecretShare(apdu);
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
        customHasher = new HashCustom();

        curve = new ECCurve(SecP256r1.p, SecP256r1.a, SecP256r1.b, SecP256r1.G, SecP256r1.r, SecP256r1.k, IndistinguishabilityApplet.rm);
        // rm = new ResourceManager((short) 256, (short) 2056);
        rng = RandomData.getInstance(RandomData.ALG_KEYGENERATION);
        dleq = new DiscreteLogEquality();
        dkg = new DistributedKeyGen(threshold, nParties);
        h2c = new HashToCurve();
        musig2 = new Musig2(curve, rm);
        if ( CARD_TYPE == OperationSupport.JCOP4_P71 ) {
            rm.fixModSqMod(curve.rBN);
        }
        aesCtr = Cipher.getInstance(Cipher_ALG_AES_CTR, false);
        // TODO change to TYPE_AES_TRANSIENT_RESET
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
        apdu.setIncomingAndReceive();
        nParties = apduBuffer[ISO7816.OFFSET_P1];
        threshold = apduBuffer[ISO7816.OFFSET_P2];

        System.out.println(String.format("Setting self index to: '%d'", apduBuffer[ISO7816.OFFSET_CDATA]));

        byte partyID = apduBuffer[ISO7816.OFFSET_CDATA];
        if ( partyID < 1 ) {
            // TODO more specific exception?
            ISOException.throwIt(Consts.SW_Exception);
        }

        dkg.partyID = partyID;
        dkg.partyIndex = (byte) (partyID - 1);
    }

    private void getSetup(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        apduBuffer[0] = nParties;
        apduBuffer[1] = threshold;
        // TODO parties are 1-indexed, but stored 0-indexed
        apduBuffer[2] =  dkg.partyID;
        apduBuffer[3] =  dkg.partyIndex;

        apdu.setOutgoingAndSend((short) 0, (short) 4);
    }

    public void generateKeyDleq(APDU apdu) {
        // TODO send out C Points and shares
        dkg.generateCoefficientsAndShares();
        // byte[] apduBuffer = apdu.getBuffer();
        // apdu.setIncomingAndReceive();

        // for (short i = 0; i < dkg.nCoeffs; i++) {
        //     short index = (short) (dkg.partyIndex * dkg.nParties + i);
        //     dkg.cPoints[index].encode(apduBuffer, (short) (i * 33), true);
        // }

        // apdu.setOutgoingAndSend((short) 0, (short) (dkg.nCoeffs * 33));
    }

    public void sendExtendedResponse(APDU apdu, byte[] input, short offset, short toSend) {
        byte[] buffer = apdu.getBuffer();

        short LE = apdu.setOutgoing();

        if (LE != toSend) {
            apdu.setOutgoingLength(toSend);
        }

        while (toSend > 0) {
            short sentLen = (extResponseChunkSize < toSend) ? extResponseChunkSize: toSend;
            Util.arrayCopyNonAtomic(input, offset, buffer, (short) 0, sentLen);
            apdu.sendBytes((short) 0, sentLen);
            toSend -= sentLen;
            offset += sentLen;
        }
    }

    public void testExtApduBuf(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        short toSend = Util.makeShort(buffer[ISO7816.OFFSET_P1], buffer[ISO7816.OFFSET_P2]);
        sendExtendedResponse(apdu, tmp, (short) 0, toSend);
    }

    public void getCPoints(APDU apdu) {
        // TODO send out C Points and shares
        short pubKeySize = 65;

        // byte[] apduBuffer = loadApdu(apdu);

        for (short i = 0; i < dkg.nCoeffs; i++) {
            short index = (short) (dkg.partyIndex * dkg.nParties + i);
            dkg.cPoints[index].encode(tmp, (short) (i * pubKeySize), false);
        }

        short length = (short) (dkg.nCoeffs * pubKeySize);
        sendExtendedResponse(apdu, tmp, (short) 0, length);
        // apdu.setOutgoing();
        // apdu.setOutgoingLength(length);
        // apdu.sendBytesLong(apduBuffer, (short) 0, length);
    }

    public void getAPoints(APDU apdu) {
        // FIXME apduBuffer unused
        byte[] apduBuffer = apdu.getBuffer();
        apdu.setIncomingAndReceive();
        // FIXME check size/offset
        short length = dkg.getAPoints(tmp);

        sendExtendedResponse(apdu, tmp, (short) 0, length);
        // apdu.setOutgoing();
        // apdu.setOutgoingLength(length);
        // apdu.sendBytesLong(apduBuffer, (short) 0, length);
    }

    public void setAPoints(APDU apdu) {
        byte[] apduBuffer = loadApdu(apdu);

        // FIXME throw if the ID is not > 0;
        byte fromPartyID = apduBuffer[ISO7816.OFFSET_P1];

        // FIXME check size/offset
        dkg.setAPoints(fromPartyID, apduBuffer, apdu.getOffsetCdata());
    }

    public void verifyAPoints(APDU apdu) {
        if ( dkg.verifyAPoints() != true ) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        dkg.computeY();
        // We assume that the dkg is done and thus set the DLEQ key
        dleq.setShare(dkg.secretShare, dkg.publicShare);
    }

    public void getDleqKey(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        short length = dkg.getGroupKey(apduBuffer, (short) 0);

        apdu.setOutgoingAndSend((short) 0, length);
    }

    public void getHashToCurve(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        short bytesRead = apdu.setIncomingAndReceive();

        h2c.hash(apduBuffer, ISO7816.OFFSET_CDATA, bytesRead, DiscreteLogEquality.tmpPoint);
        short size = DiscreteLogEquality.tmpPoint.encode(apduBuffer, (short) 0, false);

        apdu.setOutgoingAndSend((short) 0, size);
    }

    public void getDleqPublicShare(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        short length = dkg.getPublicShare(apduBuffer, (short) 0);

        apdu.setOutgoingAndSend((short) 0, length);
    }

    public void deriveDleqSaltShare(APDU apdu) {
        byte[] apduBuffer = loadApdu(apdu);

        short offset = apdu.getOffsetCdata();
        short length = dleq.partialEval(apduBuffer, offset, (short) (extApduSize - offset), apduBuffer, (short) 0);

        apdu.setOutgoing();
        apdu.setOutgoingLength(length);
        apdu.sendBytesLong(apduBuffer, (short) 0, length);
    }

    public void deriveSeedShare(APDU apdu) {
        byte[] buffer = loadApdu(apdu);
        byte[] apduBuffer = apdu.getBuffer();

        short aesCtrNonceSize = 16;
        short uncompressedECPointSize = 65;

        short offset = apdu.getOffsetCdata();
        short ctxtLen = (short) (extApduSize - aesCtrNonceSize - uncompressedECPointSize - offset);

        short ptxtLen = aesCtrDecryptInner(buffer, offset, ctxtLen, tmp, (short) 0);

        if ( !validJwt(tmp, (short) 0, ptxtLen) ) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            return;
        }

        short firstDot = indexOf(tmp, (short) 0,  ptxtLen, (byte) '.');
        short secondDot = indexOf(tmp, (short) (firstDot + 1), ptxtLen, (byte) '.');

        short dataOffset = (short) (offset + uncompressedECPointSize + aesCtrNonceSize);
        short decodLength = 0;
        decodLength = base64UrlSafeDecoder.decodeBase64Urlsafe(
            tmp,
            (short) (firstDot + 1),
            (short) (secondDot - (firstDot + 1)),
            // this possible could write againt to tmp
            buffer,
            // overwrite the initial ciphertext
            dataOffset
        );

        // FIXME add missing nonce, ephemeral key and epoch checks
        short issLength = getValueFor(buffer, dataOffset, (short) (decodLength + dataOffset), ISSUER_FIELD_NAME, procBuffer, (short) 0);
        short subLength = getValueFor(buffer, dataOffset, (short) (decodLength + dataOffset), SUBJECT_FIELD_NAME, procBuffer, issLength);

        // again overwrite now the decoded values
        short length = dleq.partialEval(procBuffer, (short) 0, (short) (issLength + subLength), buffer,  dataOffset);

        ctxtLen = aesCtrEncryptInner(buffer, offset, length, apduBuffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, ctxtLen);
    }

    public void getStableIdentifier(byte[] in, short inOffset, short length, byte[] out, short outOffset) {
        // retrieve the iss and sub values
    }

    public void getAllCPoints(APDU apdu) {
        short pubKeySize = 33;
        byte[] apduBuffer = apdu.getBuffer();

        for (short i = 0; i < (short) (dkg.nParties * dkg.nParties); i++) {
            dkg.cPoints[i].encode(apduBuffer, (short) (i * pubKeySize), true);
        }

        apdu.setOutgoingAndSend((short) 0, (short) (dkg.nParties * dkg.nParties * pubKeySize));
    }

    public void setCPoints(APDU apdu) {
        byte[] apduBuffer = loadApdu(apdu);
        byte fromPartyID = apduBuffer[ISO7816.OFFSET_P1];

        dkg.setCPoints(fromPartyID, apduBuffer, apdu.getOffsetCdata());
    }

    public void setShares(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        apdu.setIncomingAndReceive();

        byte fromPartyID = apduBuffer[ISO7816.OFFSET_P1];
        byte fromPartyIndex = (byte) (fromPartyID - 1);

        short offset = ISO7816.OFFSET_CDATA;

        // otherAShares[i] = s_i[partyID]
        // FIXME move to the DistributedKeyGen class to keep things at the same place
        short size = dkg.otherAShares[fromPartyIndex].fromByteArray(apduBuffer, offset, (short) 32);
        dkg.otherBShares[fromPartyIndex].fromByteArray(apduBuffer, (short) (offset + size), (short) 32);

        if ( dkg.verifyShares(fromPartyID) != true ) {
            // FIXME Throwing here is detectable in tests, but the shares are already set anyway.
            //       The proper way is to report the party which misbehaves.
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
        // FIXME the qualified parties should be recorded and a QUAL set of them constructed
    }

    public void computeXShare(APDU apdu) {
        dkg.computeXShare();
    }

    public void getShares(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        apdu.setIncomingAndReceive();

        byte forParty = apduBuffer[ISO7816.OFFSET_P1];
        short length = dkg.getShares(forParty, apduBuffer, (short) 0);

        apdu.setOutgoingAndSend((short) 0, length);
    }

    public void generateMusig2Key(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        apdu.setIncomingAndReceive();

        musig2.individualPubkey(apduBuffer, (short) 0);

        musig2.getPlainPubKey(apduBuffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, Constants.XCORD_LEN);
    }

    private void setUpTestData(APDU apdu) {
        // byte[] apduBuffer = apdu.getBuffer();
        byte[] apduBuffer = loadApdu(apdu);
        // apdu.setIncomingAndReceive();
        short inOffset = apdu.getOffsetCdata();
        // short inOffset = (short) 0;

        if (Constants.DEBUG == Constants.STATE_TRUE) {
            if (Constants.DEBUG != Constants.STATE_FALSE) {
                musig2.setTestingValues(apduBuffer, inOffset);
            } else {
                ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
            }
        }
    }

    public void createPartialEpoch(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        apdu.setIncomingAndReceive();
        short offsetData = apdu.getOffsetCdata();

        customHasher.init(HashCustom.INDISTINGUISHABILITY_SERVICE);
        customHasher.update(currentEpoch, (short) 0, (short) 64);
        customHasher.doFinal(apduBuffer, offsetData, (short) 32, apduBuffer, offsetData);

        short outLen = musig2.sign(
            apduBuffer,
            offsetData,
            (short) 32,
            apduBuffer,
            offsetData
        );

        apdu.setOutgoing();
        apdu.setOutgoingLength(outLen);
        apdu.sendBytesLong(apduBuffer, offsetData, outLen);
    }

    public void musigSign(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        apdu.setIncomingAndReceive();
        short offsetData = apdu.getOffsetCdata();
        // short offsetData = (short) 0;
        // short inLen = apdu.getIncomingLength();
        short inLen = (short) 32;
        // read-in the expected bitcoin hash (32B) - bound to SHA256
        // tagged_hash(b"Indistinguishabilty service", current_epoch, bitcoin_hash)
        short outLen = musig2.sign(apduBuffer,
            offsetData,
            inLen,
            apduBuffer,
            offsetData
        );

        try {
            apdu.setOutgoing();
            apdu.setOutgoingLength(outLen);
            apdu.sendBytesLong(apduBuffer, offsetData, outLen);
        } catch (CryptoException e) {
            ISOException.throwIt(Constants.E_CRYPTO_EXCEPTION);
        } catch (APDUException e) {
            ISOException.throwIt(Constants.E_BUFFER_OVERLOW);
        }
    }

    private void setAggPubKey(APDU apdu) {
        // byte[] apduBuffer = loadApdu(apdu);
        byte[] apduBuffer = apdu.getBuffer();
        apdu.setIncomingAndReceive();


        musig2.setGroupPubKey(apduBuffer, apdu.getOffsetCdata());
    }

    private void setPublicNonce(APDU apdu) {
        byte[] buffer = loadApdu(apdu);
        musig2.setNonceAggregate(buffer, apdu.getOffsetCdata());
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

        short offset = apdu.getOffsetCdata();
        short ctxtLen = (short) (extApduSize - aesCtrNonceSize - uncompressedECPointSize - zkNonceSize - offset);

        short ptxtLen = aesCtrDecryptInner(buffer, offset, ctxtLen, tmp, (short) 0);

        boolean jwtIsvalid = validJwt(tmp, (short) 0, ptxtLen);
        if ( !jwtIsvalid ) {
            Util.arrayCopyNonAtomic(Good, (short) 0, apduBuffer, (short) 0, (short) Good.length);
            apdu.setOutgoingAndSend((short) 0, (short) Good.length);
            return;
        }

        // FIXME add domain separator?
        hasher.reset();
        // zkNonce
        hasher.update(buffer, (short) (extApduSize - zkNonceSize), zkNonceSize);
        // clientPubpoint
        hasher.doFinal(buffer, offset, uncompressedECPointSize, procBuffer, (short) 0);

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
            short hashSize = deriveHashSecret(tmp, nDecoded, buffer, (short) (uncompressedECPointSize + aesCtrNonceSize + offset));
            // and encrypt it
            ctxtLen = aesCtrEncryptInner(buffer, offset, hashSize, apduBuffer, (short) 0);
            apdu.setOutgoingAndSend((short) 0, ctxtLen);
        } else {
            Util.arrayCopyNonAtomic(Bad, (short) 0, apduBuffer, (short) 0, (short) Bad.length);
            apdu.setOutgoingAndSend((short) 0, (short) Bad.length);
        }
    }

    private void verifyEncryptedJwt(APDU apdu) {
        byte[] buffer = loadApdu(apdu);
        byte[] apduBuffer = apdu.getBuffer();
        short offset = apdu.getOffsetCdata();
        short ctxtLen = (short) (extApduSize - 16 - 65 - offset);

        short ptxtLen = aesCtrDecryptInner(buffer, offset, ctxtLen, tmp, (short) 0);
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
        // FIXME the outOff is not used
        short pointLen = 65;
        byte nonceByteSize = 16;
        // generate new nonce directly to the output
        rng.nextBytes(out, (short) 0, nonceByteSize);

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
        for (short i = apdu.getOffsetCdata(); i < extApduSize; i++) {
            System.out.print(String.format("%02X", buffer[i]));
        }
        System.out.println();


        if (validJwt(buffer, apdu.getOffsetCdata(),  extApduSize)) {
            Util.arrayCopyNonAtomic(Good, (short) 0, apduBuffer, (short) 0, (short) Good.length);
            apdu.setOutgoingAndSend((short) 0, (short) Good.length);
        } else {
            Util.arrayCopyNonAtomic(Bad, (short) 0, apduBuffer, (short) 0, (short) Bad.length);
            apdu.setOutgoingAndSend((short) 0, (short) Bad.length);
        }
    }

    // FIXME validation Jwt decodes it as well, maybe it should return the decoded one if verified
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
        short payloadLength = (short) (secondDot - offset);
        return verifySignature(buffer, offset, payloadLength, derSignature, (short) 0, sigLen);
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

        short offset = apdu.getOffsetCdata();

        short firstDot = indexOf(buffer, offset,  extApduSize, (byte) '.');
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
        short offset = apdu.getOffsetCdata();

        short firstDot = indexOf(buffer, offset,  extApduSize, (byte) '.');
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
        if ( !verifySignature(buffer, offset, (short) (secondDot - offset), derSignature, (short) 0, sigLen) ) {
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

        ECPublicKey pubKey = curve.disposablePub;
        short pubKeyLength = pubKey.getW(apduBuffer, (short) 0);

        apdu.setOutgoingAndSend((short) 0, pubKeyLength);
    }

    public void generateEpochNonce(APDU apdu) {
        musig2.nonceGen();
    }

    private void getPublicNonceShare (APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        apdu.setIncomingAndReceive();
        short offsetData = apdu.getOffsetCdata();

        musig2.getPublicNonceShare(apduBuffer, offsetData);

        apdu.setOutgoing();
        apdu.setOutgoingLength((short) (Constants.POINT_LEN * Constants.V));
        apdu.sendBytesLong(apduBuffer, offsetData, (short) (Constants.XCORD_LEN * Constants.V));
    }

    public void getCurrentEpoch(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        short length = (short) currentEpoch.length;
        Util.arrayCopyNonAtomic(currentEpoch, (short) 0, buffer, (short) 0, length);

        apdu.setOutgoingAndSend((short) 0, length);
    }

    public void computeDleq(APDU apdu) {
        System.out.println("computeDleq");
        // FIXME buffer is not used
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
        DiscreteLogEquality.M.multiplication(DiscreteLogEquality.secretShare);
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

        short offset = apdu.getOffsetCdata();
        short firstDot = indexOf(buffer, offset,  extApduSize, (byte) '.');
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
    }

    public void getCommitments(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        short bytesRead = apdu.setIncomingAndReceive();

        short pubSize = 0;
        if (apduBuffer[ISO7816.OFFSET_P1] == 0x01 ) {
            pubSize = DiscreteLogEquality.com1.encode(apduBuffer, (short) 0, false);
        } else if (apduBuffer[ISO7816.OFFSET_P1] == 0x02 ) {
            pubSize = DiscreteLogEquality.com2.encode(apduBuffer, (short) 0, false);
        }

        apdu.setOutgoingAndSend((short) 0, pubSize);
    }

    public void getDleqParams(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        short bytesRead = apdu.setIncomingAndReceive();

        short genSize = DiscreteLogEquality.G.encode(apduBuffer, (short) 0, false);
        short pubSize = DiscreteLogEquality.publicShare.encode(apduBuffer, genSize, false);

        apdu.setOutgoingAndSend((short) 0, (short) (genSize + pubSize));
    }

    public void getSecretShare(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        short bytesRead = apdu.setIncomingAndReceive();

        short size = DiscreteLogEquality.secretShare.copyToByteArray(apduBuffer, (short) 0);
        apdu.setOutgoingAndSend((short) 0, size);
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

    public void echoExtApduBuffer(APDU apdu) {
        byte[] buffer = loadApdu(apdu);

        apdu.setOutgoing();
        apdu.setOutgoingLength(extApduSize);
        apdu.sendBytesLong(buffer, (short) 0, extApduSize);
    }

    private byte[] loadApdu(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        // short LC = apdu.getIncomingLength();

        short recvLen = apdu.setIncomingAndReceive(); // + apdu.getOffsetCdata());
        if (apdu.getOffsetCdata() == ISO7816.OFFSET_CDATA) {
            extApduSize = (short) (recvLen + ISO7816.OFFSET_CDATA);
            Util.arrayCopyNonAtomic(apduBuffer, (short) 0, extApduBuffer, (short) 0, extApduSize);
            return extApduBuffer;
        }

        short written = (short) (recvLen + apdu.getOffsetCdata());
        Util.arrayCopyNonAtomic(apduBuffer, (short) 0, extApduBuffer, (short) 0, written);
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
