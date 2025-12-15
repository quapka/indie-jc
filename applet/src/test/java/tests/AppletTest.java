package tests;

import cz.muni.fi.crocs.rcard.client.CardType;
import applet.IndistinguishabilityApplet;
import applet.Consts;
import applet.jcmathlib;
import org.junit.Assert;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Disabled;

import java.util.Optional;
import java.util.NoSuchElementException;

import java.util.stream.*;
import java.util.Base64;
import applet.jcmathlib.*;
import applet.Constants;
// import javacard.security.*;

import javax.crypto.KeyAgreement;
// import java.security.*;
import javax.crypto.Cipher;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.KeyFactory;
import java.security.Security;
import java.security.KeyPair;
import java.security.AlgorithmParameters;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.EllipticCurve;
import java.security.spec.ECFieldFp;
import java.security.NoSuchAlgorithmException;
import java.lang.IllegalArgumentException;

import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jcajce.provider.asymmetric.util.ECUtil;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.crypto.generators.*;
import org.bouncycastle.crypto.modes.*;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.engines.*;
import org.bouncycastle.crypto.modes.AEADCipher;
import org.bouncycastle.crypto.modes.CTRModeCipher;
import org.bouncycastle.crypto.modes.SICBlockCipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.math.BigInteger;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.SignatureAlgorithm;
import io.jsonwebtoken.io.Encoders;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.Claims;

import java.io.IOException;

import test.HashCustomTest;
import applet.HashCustom;
// import java.util.HashMap;
// import java.util.Map;
// import com.fasterxml.jackson.databind.ObjectMapper;


import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import java.util.Arrays;
import java.io.ByteArrayOutputStream;

/**
 * Example test class for the applet
 * Note: If simulator cannot be started try adding "-noverify" JVM parameter
 *
 * @author xsvenda, Dusan Klinec (ph4r05)
 */
public class AppletTest extends BaseTest {
    public static ECCurve curve;
    public static ECPoint Generator;
    public static BigInteger TWO = new BigInteger("2", 10);
    public static BigInteger THREE = new BigInteger("3", 10);
    public static BigInteger FOUR = new BigInteger("4", 10);
    public static BigInteger x;
    public static BigInteger y;
    public static BigInteger fieldPrime;
    public static BigInteger curveA;
    public static BigInteger curveB;
    public static final BigInteger curveOrder = new BigInteger(1, SecP256r1.r);
    private static final int SIGNUM_POSITIVE = 1;

    public static ECParameterSpec CURVE_SPEC = null;
    public static byte[] CURVE_P = SecP256r1.p;
    public static byte[] CURVE_R = SecP256r1.r;
    public static byte[] CURVE_A = SecP256r1.a;
    public static byte[] CURVE_B = SecP256r1.b;
    public static byte[] CURVE_G = SecP256r1.G;
    public static short CURVE_K = SecP256r1.k;
    
    public AppletTest() throws Exception {
        super();

        curve = new ECCurve.Fp(new BigInteger(1, CURVE_P), new BigInteger(1, CURVE_A), new BigInteger(1, CURVE_B));
        BigInteger x = new BigInteger(1, Arrays.copyOfRange(CURVE_G, 1, CURVE_G.length / 2 + 1));
        BigInteger y = new BigInteger(1, Arrays.copyOfRange(CURVE_G, 1 + CURVE_G.length / 2, CURVE_G.length));
        Generator = curve.createPoint(x, y);
        fieldPrime = new BigInteger(1, CURVE_P);
        curveA = new BigInteger(1, CURVE_A);
        curveB = new BigInteger(1, CURVE_B);
        CURVE_SPEC = new ECParameterSpec(curve, Generator, new BigInteger(1, CURVE_R), BigInteger.valueOf(CURVE_K));

        Security.addProvider(new BouncyCastleProvider());
    }

    @BeforeAll
    public static void setUpClass() throws Exception {
    }

    @AfterAll
    public static void tearDownClass() throws Exception {
    }

    @BeforeEach
    public void setUpMethod() throws Exception {
    }

    @AfterEach
    public void tearDownMethod() throws Exception {
    }

    @Test
    public void testDebugGood() throws Exception {
        CommandAPDU cmd = new CommandAPDU(Consts.CLA.DEBUG, Consts.INS.GOOD, 0, 0);
        ResponseAPDU responseAPDU = connect().transmit(cmd);

        Assert.assertEquals(Consts.SW.OK, (short) responseAPDU.getSW());
        Assert.assertArrayEquals(IndistinguishabilityApplet.Good, responseAPDU.getData());
    }

    @Test
    public void testDebugBad() throws Exception {
        CommandAPDU cmd = new CommandAPDU(Consts.CLA.DEBUG, Consts.INS.BAD, 0, 0);
        ResponseAPDU responseAPDU = connect().transmit(cmd);

        Assert.assertEquals(Consts.SW.OK, (short) responseAPDU.getSW());
        Assert.assertArrayEquals(IndistinguishabilityApplet.Bad, responseAPDU.getData());
    }

    @Test
    public void testIsInitialized() throws Exception {
        CommandAPDU cmd = new CommandAPDU(Consts.CLA.DEBUG, Consts.INS.IS_INITIALIZED, 0, 0);
        ResponseAPDU responseAPDU = connect().transmit(cmd);

        Assert.assertEquals(Consts.SW.OK, (short) responseAPDU.getSW());
        Assert.assertArrayEquals(new byte[] {(byte) 0xFF, (byte) 0xFF}, responseAPDU.getData());
    }

    @Test
    public void testDecodeBase64UrlSafe() throws Exception {
        SignatureAlgorithm alg = Jwts.SIG.ES256;
        KeyPair pair = alg.keyPair().build();

        String token = createToken(pair, alg);

        CommandAPDU cmd = new CommandAPDU(Consts.CLA.DEBUG, Consts.INS.DECODE_JWT, 0x00, 0, token.getBytes());
        ResponseAPDU responseAPDU = connect().transmit(cmd);

        String payload = createTokenPayload();

        Assert.assertEquals(Consts.SW.OK, (short) responseAPDU.getSW());
        // FIXME there is a buggy behaviour in the decoding routine. Currently,
        // the payload is of expected length, but if byte is added/removed, the decoded
        // data are off by one (maybe two bytes) at the end. Some unexpected null bytes
        // are added during the decoding
        Assert.assertEquals(payload.getBytes().length, responseAPDU.getData().length);
    }

    private String createTokenPayload() {
        return createTokenPayload(new byte[16]);
    }

    private String createTokenPayload(byte[] nonce) {
        String payload = "{";
        payload += "\"iss\":\"https://aexample.com\",";
        payload += "\"aud\":[\"zkLogin\"],";
        payload += "\"name\":\"Firstname Lastname\",";
        payload += "\"nonce\":\"" + Hex.toHexString(nonce).toUpperCase() + "\",";
        payload += "\"iat\":1745773527,";
        payload += "\"exp\":1745777127,";
        payload += "\"auth_time\":1745773526,";
        payload += "\"at_hash\":\"E9FuK_jSk2tTaGXQQ0MzXA\",";
        payload += "\"sub\":\"12\"}";

        return payload;
    }

    private String createToken(KeyPair pair, SignatureAlgorithm alg) {
        return createToken(pair, alg, new byte[16]);
    }

    private String createToken(KeyPair pair, SignatureAlgorithm alg, byte[] nonce) {
        String payload = createTokenPayload(nonce);

        return Jwts.builder()
            .setHeaderParam("alg", "ES256")
            .setHeaderParam("typ", "JWT")
            .setHeaderParam("kid", "example")
            .setPayload(payload)
            .signWith(pair.getPrivate(), alg)
            .compact();
    }

    @Test
    public void testDerivingSalt() throws Exception {
        SignatureAlgorithm alg = Jwts.SIG.ES256;
        KeyPair pair = alg.keyPair().build();

        String token = createToken(pair, alg);

        KeyFactory keyFact = KeyFactory.getInstance("ECDSA", "BC");
        ECPublicKeySpec pubSpec = keyFact.getKeySpec(pair.getPublic(), ECPublicKeySpec.class);
        boolean compressed = false;
        // FIXME use compressed to speed up processing and shorten data payloads?
        byte[] uncompressedPubKey = pubSpec.getQ().getEncoded(compressed);

        // Set and implicitly get the public key
        connect().transmit(new CommandAPDU(Consts.CLA.INDIE, Consts.INS.SET_OIDC_PUBKEY, 0x00, 0x00, uncompressedPubKey));

        CommandAPDU cmd = new CommandAPDU(Consts.CLA.DEBUG, Consts.INS.DERIVE_SALT, 0x00, 0, token.getBytes());
        ResponseAPDU responseAPDU = connect().transmit(cmd);

        byte[] salt = responseAPDU.getData();

        Assert.assertEquals(salt.length, 32);
        // For simulated tests, the on card keys are generated
        // deterministically, thus we can assert against a known key
        if ( IndistinguishabilityApplet.CARD_TYPE == jcmathlib.OperationSupport.SIMULATOR ){
            Assert.assertEquals("6a5323256f3ff924017ae2ebbbd56e2556192e1f322e991b911e56069c17976d", Hex.toHexString(salt));
        }
    }

    @Test
    public void testGettingExampleDleqProof() throws Exception {
        SignatureAlgorithm alg = Jwts.SIG.ES256;
        KeyPair pair = alg.keyPair().build();

        String token = createToken(pair, alg);

        byte[] byteToken = token.getBytes();

        CommandAPDU cmd = new CommandAPDU(Consts.CLA.INDIE, Consts.INS.GET_EXAMPLE_PROOF, 0x00, 0, byteToken);
        ResponseAPDU responseAPDU = connect().transmit(cmd);

        System.out.println(String.format("byteInput length: %d", byteToken.length));
        System.out.println(String.format("Received: %d", responseAPDU.getData().length));
    }

    @Test
    public void testDVRFKeyGeneration() throws Exception {
        CommandAPDU cmd = new CommandAPDU(Consts.CLA.INDIE, Consts.INS.KEY_GEN, 0x00, 0);
        ResponseAPDU responseAPDU = connect().transmit(cmd);

        Assert.assertEquals(responseAPDU.getData().length, 1 + 32 + 32);
    }

    // FIXME Occasional failure:
    // AppletTest > testDLEQAgainstGeneratedKey() STANDARD_OUT
    // DEBUG | 2025-10-14 21:44:20 | [Test worker] client.CardManager:163 | Looking for physical cards...
    // DEBUG | 2025-10-14 21:44:20 | [Test worker] client.CardManager:268 | Connecting...
    // DEBUG | 2025-10-14 21:44:20 | [Test worker] client.CardManager:273 | Terminal connected
    // DEBUG | 2025-10-14 21:44:20 | [Test worker] client.CardManager:275 | Establishing channel...
    // DEBUG | 2025-10-14 21:44:20 | [Test worker] client.CardManager:277 | Channel established
    // DEBUG | 2025-10-14 21:44:20 | [Test worker] client.CardManager:262 | Smartcard: Selecting applet...
    // DEBUG | 2025-10-14 21:44:20 | [Test worker] client.Util:120 | --> [00A404000D01FFFF04050607080901020102] (18 B)
    // DEBUG | 2025-10-14 21:44:20 | [Test worker] client.Util:130 | <-- 9000
    // DEBUG | 2025-10-14 21:44:20 | [Test worker] client.Util:133 | Elapsed time 20 ms
    // DEBUG | 2025-10-14 21:44:20 | [Test worker] client.Util:120 | --> [0002000000] (5 B)
    // DEBUG | 2025-10-14 21:44:21 | [Test worker] client.Util:127 | <-- 040A7502F80BE6572C71A48939BF44B768C526FB73EBF9AE25E99B81B882EE2A6B3D14C3DDFD7FC2B602B4135BD222EB32942C14B45765986F04DD01CEAB2C86F2 9000 (65 B)
    // DEBUG | 2025-10-14 21:44:21 | [Test worker] client.Util:133 | Elapsed time 228 ms

    // #
    // # A fatal error has been detected by the Java Runtime Environment:
    // #
    // #  SIGSEGV (0xb) at pc=0x00007fffb8145970, pid=476611, tid=0x00007fffb9d396c0
    // #
    // # JRE version: OpenJDK Runtime Environment (8.0_442) (build 1.8.0_442-06)
    // # Java VM: OpenJDK 64-Bit Server VM (25.442-b06 mixed mode linux-amd64 compressed oops)
    // # Problematic frame:
    // # C  0x00007fffb8145970
    // #
    // # Core dump written. Default location: /home/qup/projects/indie-jc/applet/core or core.476611
    // #
    // # An error report file with more information is saved as:
    // # /home/qup/projects/indie-jc/applet/hs_err_pid476611.log
    // #
    // # If you would like to submit a bug report, please visit:
    // #   http://bugreport.java.com/bugreport/crash.jsp
    // #
    @Test
    public void testDLEQAgainstGeneratedKey() throws Exception {
        CommandAPDU cmd = new CommandAPDU(Consts.CLA.INDIE, Consts.INS.KEY_GEN, 0x00, 0);
        ResponseAPDU responseAPDU = connect().transmit(cmd);
        byte[] data = responseAPDU.getData();

        BigInteger xCoord = new BigInteger(SIGNUM_POSITIVE, Arrays.copyOfRange(data, 1, 33));
        BigInteger yCoord = new BigInteger(SIGNUM_POSITIVE, Arrays.copyOfRange(data, 35, 65));
        ECPoint dvrfPubPoint = curve.createPoint(xCoord, yCoord);
        // FIXME do assertions
    }

    @Test
    public void testSetup() throws Exception {
        byte threshold = 0x02;
        byte nParties = 0x03;
        CommandAPDU setupCmd = new CommandAPDU(Consts.CLA.INDIE, Consts.INS.SETUP, nParties, threshold);
        ResponseAPDU responseAPDU = connect().transmit(setupCmd);

        CommandAPDU getSetupCmd = new CommandAPDU(Consts.CLA.INDIE, Consts.INS.GET_SETUP, 0, 0);
        responseAPDU = connect().transmit(getSetupCmd);
        byte[] data = responseAPDU.getData();

        Assert.assertEquals(data[0], nParties);
        Assert.assertEquals(data[1], threshold);
    }

    public void printBuffer(byte[] buf, short size) {
        for(short i = 0; i < size; i++) {
            System.out.print(String.format("%02x", buf[i]));
        }
        System.out.println();
    }

    @Test
    public void testAesCtrDecryption() throws Exception {
        CommandAPDU cmd = new CommandAPDU(Consts.CLA.INDIE, Consts.INS.KEY_GEN, 0x00, 0);
        ResponseAPDU responseAPDU = connect().transmit(cmd);
        byte[] data = responseAPDU.getData();

        byte[] seed = new byte[32];
        SecureRandom prng = new SecureRandom(seed);

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDH", "BC");
        KeyFactory keyFact = KeyFactory.getInstance("ECDH", "BC");
        ECNamedCurveParameterSpec namedSpec = ECNamedCurveTable.getParameterSpec("secP256r1");
        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("secP256r1");
        ECPublicKeySpec dvrfPubSpec = new ECPublicKeySpec(curve.decodePoint(data), namedSpec);
        ECPublicKey dvrfPubKey = (ECPublicKey) keyFact.generatePublic(dvrfPubSpec);
        System.out.println(dvrfPubKey);

        // TODO the RNG seed does not produce fixed keys for the test
        kpg.initialize(ecGenSpec, new SecureRandom());
        KeyPair keyPair = kpg.generateKeyPair();
        ECPublicKey pubKey = (ECPublicKey) keyPair.getPublic();
        System.out.println(pubKey);

        KeyAgreement ecdh = KeyAgreement.getInstance("ECDH", "BC");
        ecdh.init(keyPair.getPrivate());
        ecdh.doPhase(dvrfPubKey, true);

        ECPublicKeySpec bcPubSpec = keyFact.getKeySpec(pubKey, ECPublicKeySpec.class);
        // TODO does sending compressed point speed up the operations?
        // Need to consider also the uncompressing inside the card.
        boolean compressed = false;
        byte[] encodedPubKey = bcPubSpec.getQ().getEncoded(compressed);

        byte[] sharedSecret = ecdh.generateSecret();
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        byte[] derivedKey = sha1.digest(sharedSecret);

        byte[] ecdhKey = Arrays.copyOf(derivedKey, 20);

        byte nonceByteSize = 16;
        byte[] nonce = new byte[nonceByteSize];
        prng.nextBytes(nonce);

        KeyParameter ctrKey = new KeyParameter(ecdhKey, 0, 16);
        short macSizeBits = 128;
        CTRModeCipher cipher = new SICBlockCipher(new AESEngine());
        ParametersWithIV params = new ParametersWithIV(ctrKey, nonce);

        boolean forEncryption = true;
        cipher.init(forEncryption, params);
        byte[] ctxtBuff = new byte[256];

        String message = "this is my message";
        byte[] msgBytes = message.getBytes();

        int ctxtLen = cipher.processBytes(msgBytes, 0, msgBytes.length, ctxtBuff, 0);
        System.out.println("Calculated ciphertext.");
        printBuffer(ctxtBuff, (short) ctxtLen);

        byte[] encPayload = new byte [65 + nonceByteSize + ctxtLen];
        System.out.println(String.format("encodedPubKey length: %d", encodedPubKey.length));
        System.arraycopy(encodedPubKey, 0, encPayload, 0, encodedPubKey.length);
        System.arraycopy(nonce, 0, encPayload, encodedPubKey.length, nonceByteSize);
        System.arraycopy(ctxtBuff, 0, encPayload, nonceByteSize + encodedPubKey.length, ctxtLen);

        cmd = new CommandAPDU(Consts.CLA.DEBUG, Consts.INS.AES_CTR_DECRYPT, (byte) ctxtLen, nonceByteSize, encPayload, 0, encodedPubKey.length + nonceByteSize + ctxtLen);
        responseAPDU = connect().transmit(cmd);

        Assert.assertArrayEquals(msgBytes, responseAPDU.getData());
    }

    public byte[] nonceZkLogin() throws Exception {
        byte[] seed = new byte[32];
        SecureRandom prng = new SecureRandom(seed);

        MessageDigest hasher = MessageDigest.getInstance("SHA-256");
        // Source: https://arxiv.org/pdf/2401.11735 page 8
        // nonce ← 𝐻 (𝑣𝑘𝑢, T_max, 𝑟)
        byte[] ephemeralPubKey = new byte[32];
        byte[] timeMax = new byte[32];
        byte[] random = new byte[32];

        prng.nextBytes(ephemeralPubKey);
        prng.nextBytes(timeMax); // User random value for the T_max time
        prng.nextBytes(random);

        hasher.update(ephemeralPubKey);
        hasher.update(timeMax);
        hasher.update(random);

        return hasher.digest();
    }

    @Test
    public void testVerifyCommitment() throws Exception {
        // Generate ephemeral public
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("secP256r1");
        kpg.initialize(ecGenSpec, new SecureRandom());
        KeyPair keyPair = kpg.generateKeyPair();
        ECPublicKey pubKey = (ECPublicKey) keyPair.getPublic();

        // TODO does sending compressed point speed up the operations?
        // Need to consider also the uncompressing inside the card.
        KeyFactory keyFact = KeyFactory.getInstance("ECDSA", "BC");
        ECPublicKeySpec pubSpec = keyFact.getKeySpec(pubKey, ECPublicKeySpec.class);
        boolean compressed = false;
        byte[] encodedPubKey = pubSpec.getQ().getEncoded(compressed);

        MessageDigest hasher = MessageDigest.getInstance("SHA-256");

        byte[] zkNonce = nonceZkLogin();
        hasher.update(zkNonce);
        hasher.update(encodedPubKey);
        byte[] merkleeTree = hasher.digest();

        short compressedKeySize = 65;
        byte[] payload = new byte [zkNonce.length + encodedPubKey.length + merkleeTree.length];
        printBuffer(payload, (short) payload.length);

        // System.out.println(String.format("encodedPubKey length: %d", encodedPubKey.length));
        System.arraycopy(zkNonce, 0, payload, 0, zkNonce.length);
        System.arraycopy(encodedPubKey, 0, payload, zkNonce.length, encodedPubKey.length);
        System.arraycopy(merkleeTree, 0, payload, zkNonce.length + encodedPubKey.length, merkleeTree.length);

        // send zkNonce, merkleeTree, and pubKey and let the card verify it
        CommandAPDU cmd = new CommandAPDU(Consts.CLA.DEBUG, Consts.INS.VERIFY_COMMITMENT, zkNonce.length, encodedPubKey.length, payload, 0, payload.length);
        ResponseAPDU responseAPDU = connect().transmit(cmd);
        System.out.println(String.format("\"%s\"", new String(responseAPDU.getData(), "UTF-8")));

        Assert.assertEquals(Consts.SW.OK, (short) responseAPDU.getSW());
        Assert.assertArrayEquals(IndistinguishabilityApplet.Good, responseAPDU.getData());
    }

    @Test
    public void testSetOIDCPublicKey() throws Exception {
        SignatureAlgorithm alg = Jwts.SIG.ES256;
        KeyPair pair = alg.keyPair().build();

        KeyFactory keyFact = KeyFactory.getInstance("ECDSA", "BC");
        ECPublicKeySpec pubSpec = keyFact.getKeySpec(pair.getPublic(), ECPublicKeySpec.class);
        boolean compressed = false;
        // FIXME use compressed to speed up processing and shorten data payloads?
        byte[] uncompressedPubKey = pubSpec.getQ().getEncoded(compressed);

        // Set and implicitly get the public key
        CommandAPDU cmd = new CommandAPDU(Consts.CLA.INDIE, Consts.INS.SET_OIDC_PUBKEY, 0x00, 0x00, uncompressedPubKey);
        ResponseAPDU responseAPDU = connect().transmit(cmd);

        Assert.assertEquals(Consts.SW.OK, (short) responseAPDU.getSW());
        Assert.assertArrayEquals(uncompressedPubKey, responseAPDU.getData());

        // Explicitly get the public key again
        cmd = new CommandAPDU(Consts.CLA.INDIE, Consts.INS.GET_OIDC_PUBKEY, 0x00, 0x00);
        responseAPDU = connect().transmit(cmd);

        Assert.assertEquals(Consts.SW.OK, (short) responseAPDU.getSW());
        Assert.assertArrayEquals(uncompressedPubKey, responseAPDU.getData());
    }

    @Test
    public void testJWTVerification() throws Exception {
        SignatureAlgorithm alg = Jwts.SIG.ES256;
        KeyPair pair = alg.keyPair().build();

        KeyFactory keyFact = KeyFactory.getInstance("ECDSA", "BC");
        ECPublicKeySpec pubSpec = keyFact.getKeySpec(pair.getPublic(), ECPublicKeySpec.class);
        boolean compressed = false;
        // FIXME use compressed to speed up processing and shorten data payloads?
        byte[] uncompressedPubKey = pubSpec.getQ().getEncoded(compressed);

        // Set and implicitly get the public key
        CommandAPDU cmd = new CommandAPDU(Consts.CLA.INDIE, Consts.INS.SET_OIDC_PUBKEY, 0x00, 0x00, uncompressedPubKey);
        ResponseAPDU responseAPDU = connect().transmit(cmd);

        byte nonceByteSize = 16;
        byte[] nonce = new byte[nonceByteSize];

        byte[] seed = new byte[32];
        SecureRandom prng = new SecureRandom(seed);
        prng.nextBytes(nonce);

        // Create the JWT
        String payload = "{\"aud\":\"zkLogin\",\"name\":\"FirstnameLastName\",\"nonce\":\""+ Hex.toHexString(nonce) + "\"}";
        String jwt = Jwts.builder()
            .setPayload(payload)
            .signWith(pair.getPrivate(), alg)
            .compact();

        System.out.print(jwt);
        cmd = new CommandAPDU(Consts.CLA.DEBUG, Consts.INS.VERIFY_JWT, 0x00, 0x00, jwt.getBytes());
        responseAPDU = connect().transmit(cmd);

        Assert.assertEquals(Consts.SW.OK, (short) responseAPDU.getSW());
        Assert.assertArrayEquals(IndistinguishabilityApplet.Good, responseAPDU.getData());
    }

    @Test
    public void testEncryptedJwtVerification() throws Exception {
        byte[] seed = new byte[32];
        SecureRandom prng = new SecureRandom(seed);

        SignatureAlgorithm alg = Jwts.SIG.ES256; //or ES256 or ES384
        KeyPair pair = alg.keyPair().build();

        KeyFactory ecKeyFact = KeyFactory.getInstance("ECDSA", "BC");
        ECPublicKeySpec pubSpec = ecKeyFact.getKeySpec(pair.getPublic(), ECPublicKeySpec.class);
        boolean compressed = false;
        // FIXME use compressed to speed up processing and shorten data payloads?
        byte[] uncompressedPubKey = pubSpec.getQ().getEncoded(compressed);

        // Set and implicitly get the public key
        connect().transmit(new CommandAPDU(Consts.CLA.INDIE, Consts.INS.SET_OIDC_PUBKEY, 0x00, 0x00, uncompressedPubKey));

        // Encrypt the token first and then verify it inside the card
        CommandAPDU cmd = new CommandAPDU(Consts.CLA.INDIE, Consts.INS.KEY_GEN, 0x00, 0);
        ResponseAPDU responseAPDU = connect().transmit(cmd);
        byte[] data = responseAPDU.getData();

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDH", "BC");
        KeyFactory echdKeyFact = KeyFactory.getInstance("ECDH", "BC");
        ECNamedCurveParameterSpec namedSpec = ECNamedCurveTable.getParameterSpec("secP256r1");
        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("secP256r1");
        ECPublicKeySpec dvrfPubSpec = new ECPublicKeySpec(curve.decodePoint(data), namedSpec);
        ECPublicKey cardChannelKey = (ECPublicKey) echdKeyFact.generatePublic(dvrfPubSpec);

        // TODO the RNG seed does not produce fixed keys for the test
        kpg.initialize(ecGenSpec, new SecureRandom());
        KeyPair epheClientChannelKey = kpg.generateKeyPair();
        ECPublicKey epheClientPubKey = (ECPublicKey) epheClientChannelKey.getPublic();

        KeyAgreement ecdh = KeyAgreement.getInstance("ECDH", "BC");
        ecdh.init(epheClientChannelKey.getPrivate());
        ecdh.doPhase(cardChannelKey, true);

        ECPublicKeySpec epheClientPubKeySpec = echdKeyFact.getKeySpec(epheClientPubKey, ECPublicKeySpec.class);
        // TODO does sending compressed point speed up the operations?
        // Need to consider also the uncompressing inside the card.
        compressed = false;
        byte[] encodedClientPubPoint = epheClientPubKeySpec.getQ().getEncoded(compressed);

        byte[] sharedSecret = ecdh.generateSecret();
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        byte[] fullChannelKey = sha1.digest(sharedSecret);

        byte[] channelKey = Arrays.copyOf(fullChannelKey, 20);
        System.out.println("Channel key");
        for (short i = 0; i < 20; i++) {
            System.out.print(String.format("%02X", channelKey[i]));
        }
        System.out.println();

        byte channelNonceByteSize = 16;
        byte[] channelNonce = new byte[channelNonceByteSize];
        prng.nextBytes(channelNonce);

        KeyParameter ctrKey = new KeyParameter(channelKey, 0, 16);
        short macSizeBits = 128;
        CTRModeCipher cipher = new SICBlockCipher(new AESEngine());
        ParametersWithIV params = new ParametersWithIV(ctrKey, channelNonce);

        boolean forEncryption = true;
        cipher.init(forEncryption, params);

        byte tokenNonceByteSize = 16;
        byte[] tokenNonce = new byte[tokenNonceByteSize];
        prng.nextBytes(tokenNonce);

        System.out.println("Channel IV");
        for (short i = 0; i < channelNonceByteSize; i++) {
            System.out.print(String.format("%02X", channelNonce[i]));
        }
        System.out.println();

        String jwt = createToken(pair, alg, tokenNonce);

        System.out.println(String.format("Token length: %d", jwt.getBytes().length));
        System.out.println("In-test token");
        // for (short i = 0; i < ; i++) {
        //     System.out.print(String.format("%02X", procBuffer[i]));
        // }
        System.out.println(jwt);

        byte[] ctxtBuff = new byte[2048];
        int ctxtLen = cipher.processBytes(jwt.getBytes(), 0, jwt.getBytes().length, ctxtBuff, 0);

        byte[] encPayload = new byte [65 + channelNonceByteSize + ctxtLen];
        // System.out.println(String.format("encodedClientPubPoint length: %d", encodedClientPubPoint.length));
        System.arraycopy(encodedClientPubPoint, 0, encPayload, 0, encodedClientPubPoint.length);
        System.arraycopy(channelNonce, 0, encPayload, encodedClientPubPoint.length, channelNonceByteSize);
        System.arraycopy(ctxtBuff, 0, encPayload, channelNonceByteSize + encodedClientPubPoint.length, ctxtLen);

        cmd = new CommandAPDU(Consts.CLA.DEBUG, Consts.INS.VERIFY_JWT, 0x00, 0x00, jwt.getBytes());
        responseAPDU = connect().transmit(cmd);

        Assert.assertArrayEquals(IndistinguishabilityApplet.Good, responseAPDU.getData());

        cmd = new CommandAPDU(Consts.CLA.DEBUG, Consts.INS.VERIFY_ENCRYPTED_JWT, 0x00, 0x00, encPayload, 0, encodedClientPubPoint.length + channelNonceByteSize + ctxtLen);
        responseAPDU = connect().transmit(cmd);

        printBuffer(responseAPDU.getBytes(), (short) 4);

        Assert.assertArrayEquals(IndistinguishabilityApplet.Good, responseAPDU.getData());
    }

    @Disabled("Don't run routinely")
    @Test
    public void testBenchmarkDecoding() throws Exception {
        String encoded = "Dk8SWM_Z3oZB-uwzAmTL9e4c1AGqpBAKNe2x56k9dWnCUL3gpRRpO-kUsgWtCDaUTjrNWsrbHtdpSlgoxKoYy6fXokmmylaS_Bw1x8nC--wZQAtoZCsA96yRFRz3ywFjS1lRzRc6s7YE10cRVMAD_qE68Y9WTo50G_GQlGruZg3h4pO2DYrDMNGhArE89o2kGCReFZIhUplYEREveCEoC77p59D2kIPX9vo7kuiKIfkYPd";

        byte[] expected = Base64.getUrlDecoder().decode(encoded);


        long starTime = 0;
        long endTime = 0;
        int numTests = 20;
        long[] results = new long[numTests];
        CommandAPDU cmd = new CommandAPDU(Consts.CLA.DEBUG, Consts.INS.DECODE_JWT, 0x00, 0, ("." + encoded + ".").getBytes());
        ResponseAPDU responseAPDU = connect().transmit(cmd);
        for (int i = 0; i < numTests; i++) {
            starTime = System.nanoTime();
            responseAPDU = connect().transmit(cmd);
            results[i] = System.nanoTime() - starTime;
            Assert.assertEquals(Consts.SW.OK, (short) responseAPDU.getSW());
        }
        // 646138521
        // Inline switch
        // 787456532
        // Switch
        // 655532144
        // Switch + unwounded j-loop
        // 937848861
        // for
        // 1620959263
        long sum = LongStream.of(results).sum();
        System.out.println("Average decoding time: " + (sum / results.length) + " ns");
    }

    @Test
    public void testEncryptedJwtVerificationAndCommitment() throws Exception {
        byte[] seed = new byte[32];
        SecureRandom prng = new SecureRandom(seed);

        SignatureAlgorithm alg = Jwts.SIG.ES256; //or ES256 or ES384
        KeyPair pair = alg.keyPair().build();

        KeyFactory ecKeyFact = KeyFactory.getInstance("ECDSA", "BC");
        ECPublicKeySpec pubSpec = ecKeyFact.getKeySpec(pair.getPublic(), ECPublicKeySpec.class);
        boolean compressed = false;
        // FIXME use compressed to speed up processing and shorten data payloads?
        byte[] uncompressedPubKey = pubSpec.getQ().getEncoded(compressed);

        // Set and implicitly get the public key
        connect().transmit(new CommandAPDU(Consts.CLA.INDIE, Consts.INS.SET_OIDC_PUBKEY, 0x00, 0x00, uncompressedPubKey));

        // Encrypt the token first and then verify it inside the card
        CommandAPDU cmd = new CommandAPDU(Consts.CLA.INDIE, Consts.INS.KEY_GEN, 0x00, 0);
        ResponseAPDU responseAPDU = connect().transmit(cmd);
        byte[] data = responseAPDU.getData();

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDH", "BC");
        KeyFactory echdKeyFact = KeyFactory.getInstance("ECDH", "BC");
        ECNamedCurveParameterSpec namedSpec = ECNamedCurveTable.getParameterSpec("secP256r1");
        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("secP256r1");
        ECPublicKeySpec dvrfPubSpec = new ECPublicKeySpec(curve.decodePoint(data), namedSpec);
        ECPublicKey cardChannelKey = (ECPublicKey) echdKeyFact.generatePublic(dvrfPubSpec);

        // TODO the RNG seed does not produce fixed keys for the test
        kpg.initialize(ecGenSpec, new SecureRandom());
        KeyPair epheClientChannelKey = kpg.generateKeyPair();
        ECPublicKey epheClientPubKey = (ECPublicKey) epheClientChannelKey.getPublic();

        KeyAgreement ecdh = KeyAgreement.getInstance("ECDH", "BC");
        ecdh.init(epheClientChannelKey.getPrivate());
        ecdh.doPhase(cardChannelKey, true);

        ECPublicKeySpec epheClientPubKeySpec = echdKeyFact.getKeySpec(epheClientPubKey, ECPublicKeySpec.class);
        // TODO does sending compressed point speed up the operations?
        // Need to consider also the uncompressing inside the card.
        compressed = false;
        byte[] encodedClientPubPoint = epheClientPubKeySpec.getQ().getEncoded(compressed);

        byte[] sharedSecret = ecdh.generateSecret();
        MessageDigest sha1 = MessageDigest.getInstance("SHA-1");
        byte[] fullChannelKey = sha1.digest(sharedSecret);

        byte[] channelKey = Arrays.copyOf(fullChannelKey, 20);

        byte channelNonceByteSize = 16;
        byte[] channelNonce = new byte[channelNonceByteSize];
        prng.nextBytes(channelNonce);

        KeyParameter ctrKey = new KeyParameter(channelKey, 0, 16);
        short macSizeBits = 128;
        CTRModeCipher cipher = new SICBlockCipher(new AESEngine());
        ParametersWithIV params = new ParametersWithIV(ctrKey, channelNonce);

        boolean forEncryption = true;
        cipher.init(forEncryption, params);

        byte[] zkNonce = nonceZkLogin();
        MessageDigest hasher = MessageDigest.getInstance("SHA-256");
        hasher.update(zkNonce);
        hasher.update(encodedClientPubPoint);
        byte[] tokenNonce = hasher.digest();

        String jwt = createToken(pair, alg, tokenNonce);

        byte[] ctxtBuff = new byte[2048];
        int ctxtLen = cipher.processBytes(jwt.getBytes(), 0, jwt.getBytes().length, ctxtBuff, 0);

        // Build the payload
        // List<Byte> temp = new ArrayList<>();
        byte[] encPayload = new byte [encodedClientPubPoint.length + channelNonceByteSize + ctxtLen + zkNonce.length];
        short payloadLength = 0;
        System.arraycopy(encodedClientPubPoint, 0, encPayload, payloadLength, encodedClientPubPoint.length);
        payloadLength += encodedClientPubPoint.length;

        System.arraycopy(channelNonce, 0, encPayload, payloadLength, channelNonceByteSize);
        payloadLength += channelNonceByteSize;

        System.arraycopy(ctxtBuff, 0, encPayload, payloadLength, ctxtLen);
        payloadLength += ctxtLen;

        System.arraycopy(zkNonce, 0, encPayload, payloadLength, zkNonce.length);
        payloadLength += zkNonce.length;

        cmd = new CommandAPDU(Consts.CLA.DEBUG, Consts.INS.VERIFY_ENCRYPTED_JWT_AND_COMMITMENT, 0x00, 0x00, encPayload, 0, payloadLength);
        responseAPDU = connect().transmit(cmd);

        System.arraycopy(responseAPDU.getData(), 0, channelNonce, 0, channelNonceByteSize);
        params = new ParametersWithIV(ctrKey, channelNonce);

        forEncryption = false;
        cipher.init(forEncryption, params);

        byte[] ptxtBuff = new byte[32];
        int ptxtLen = cipher.processBytes(responseAPDU.getData(), channelNonceByteSize, responseAPDU.getData().length - channelNonceByteSize, ptxtBuff, 0);
        // NOTE This hardcoded salt works for the hash-based derivation that
        // uses hardcoded secret and a test user
        byte[] expectedSalt = Hex.decode("6a5323256f3ff924017ae2ebbbd56e2556192e1f322e991b911e56069c17976d");

        Assert.assertArrayEquals(expectedSalt, ptxtBuff);
    }

    @Test
    public void testGetCurrentEmptyEpoch() throws Exception {
        byte[] expectedEpoch = new byte[64];

        CommandAPDU cmd = new CommandAPDU(Consts.CLA.INDIE, Consts.INS.GET_CURRENT_EPOCH, 0x00, 0x00);
        ResponseAPDU responseAPDU = connect().transmit(cmd);
        byte[] data = responseAPDU.getData();

        Assert.assertEquals(Consts.SW.OK, (short) responseAPDU.getSW());
        Assert.assertArrayEquals(expectedEpoch, data);
    }

    @Test
    public void testGenerateMusig2Key() throws Exception {

        CommandAPDU cmd = new CommandAPDU(Consts.CLA.INDIE, Consts.INS.GENERATE_KEY_MUSIG2, 0x00, 0);
        ResponseAPDU responseAPDU = connect().transmit(cmd);
        byte[] data = responseAPDU.getData();

        Assert.assertEquals(Consts.SW.OK, (short) responseAPDU.getSW());
        Assert.assertEquals(Constants.XCORD_LEN, data.length);
    }

    @Test
    public void testGenerateMusig2Nonce() throws Exception {
        CommandAPDU cmd = new CommandAPDU(Consts.CLA.INDIE, Consts.INS.GENERATE_KEY_MUSIG2, 0x00, 0);
        ResponseAPDU responseAPDU = connect().transmit(cmd);

        Assert.assertEquals("Got NOK from card", Consts.SW.OK, (short) responseAPDU.getSW());

        cmd = new CommandAPDU(Consts.CLA.INDIE, Consts.INS.GENERATE_NONCE_MUSIG2, 0x00, 0);
        responseAPDU = connect().transmit(cmd);

        Assert.assertEquals("Got NOK from card", Consts.SW.OK, (short) responseAPDU.getSW());

        cmd = new CommandAPDU(Consts.CLA.INDIE, Consts.INS.GET_PUBLIC_NONCE_SHARE, 0x00, 0);
        responseAPDU = connect().transmit(cmd);
        System.out.println(Hex.toHexString(responseAPDU.getData()));

        Assert.assertEquals("Got NOK from card", Consts.SW.OK, (short) responseAPDU.getSW());
        Assert.assertEquals(
            "Did not get expected number of bytes from the card.",
            Constants.XCORD_LEN * Constants.V,
            (short) responseAPDU.getData().length
        );

        Assert.assertTrue(
            "The public nonce cannot be decoded into a valid ECPoint.",
            !curve.decodePoint(Arrays.copyOfRange(responseAPDU.getData(), 0, 33)).isInfinity()
        );
        Assert.assertTrue(
            "The public nonce cannot be decoded into a valid ECPoint.",
            !curve.decodePoint(Arrays.copyOfRange(responseAPDU.getData(), 33, 66)).isInfinity()
        );
    }

    public byte[] getSecondKeyPlain(ECPoint[] pubkeys) {
        for (int j = 1; j < pubkeys.length; j++ ) {
            if ( ! pubkeys[j].equals(pubkeys[0]) ) {
                return pubkeys[j].getEncoded(true);
            }
        }
        return new byte[33];
    }

    public ECPoint keyAgg(ECPoint[] pubkeys) throws NoSuchAlgorithmException {
        byte[] pk2 = getSecondKeyPlain(pubkeys);
        ECPoint Q = curve.getInfinity();

        for ( int i = 0; i < pubkeys.length; i++ ) {
            // NOTE pubkeys shall be bytes and here is where we can catch an invalid contribution
            // pubkeys[i];
            BigInteger a_i = keyAggCoeffInternal(pubkeys, pubkeys[i], pk2);
            Q = Q.add(pubkeys[i].multiply(a_i));
        }
        return Q;
    }

    public BigInteger keyAggCoeff(ECPoint[] pubkeys, ECPoint pk) throws NoSuchAlgorithmException {
        byte[] pk2 = getSecondKeyPlain(pubkeys);
        return keyAggCoeffInternal(pubkeys, pk, pk2);
    }

    public BigInteger keyAggCoeffInternal(ECPoint[] pubkeys, ECPoint pk, byte[] pk2) throws NoSuchAlgorithmException {
        byte[] L = hashKeys(pubkeys);
        if ( Arrays.equals(pk.getEncoded(true), pk2) ) {
            return BigInteger.ONE;
        }
        HashCustomTest hasher = new HashCustomTest();
        hasher.init("KeyAgg coefficient");
        // return int_from_bytes(tagged_hash('KeyAgg coefficient', L + pk_)) % n
        hasher.update(L);
        hasher.update(pk.getEncoded(true));

        return (new BigInteger(1, hasher.digest())).mod(curveOrder);
    }

    public byte[] hashKeys(ECPoint[] pubkeys) throws NoSuchAlgorithmException{
        HashCustomTest hasher = new HashCustomTest();
        hasher.init("KeyAgg list");

        for(int i = 0; i < pubkeys.length; i++) {
            hasher.update(pubkeys[i].getEncoded(true));
        }
        return hasher.digest();
    }

    private BigInteger generateCoefB(byte[] message, ECPoint[] aggNonces, ECPoint aggregatedKey) throws NoSuchAlgorithmException {
        HashCustomTest hasher = new HashCustomTest();
        hasher.init(HashCustom.MUSIG_NONCECOEF);

        // Hash public aggregated nonces
        for (short i = 0; i < Constants.V; i++) {
            hasher.update(aggNonces[i].getEncoded(true));
        }

        // Hash public key
        // Must be encoded using xbytes, notice the `normalize()`
        hasher.update(aggregatedKey.normalize().getXCoord().getEncoded());
        // or get X-coord directly from the encoded public key instead
        // hasher.update(Arrays.copyOfRange(aggregatedKey.getEncoded(true), 1, 33));

        // Hash the message to be signed
        byte[] digest = hasher.digest(message);
        BigInteger coefB = (new BigInteger(1, digest)).mod(curveOrder);
        return coefB;
    }

    private ECPoint generateCoefR(BigInteger coefB, ECPoint[] aggNonces) {
        return aggNonces[1].multiply(coefB).add(aggNonces[0]);
    }

    private BigInteger generateChallengeE(byte[] message, ECPoint coefR, ECPoint aggregatedKey) throws NoSuchAlgorithmException {
        HashCustomTest hasher = new HashCustomTest();
        hasher.init(HashCustom.BIP_CHALLENGE);

        hasher.update(coefR.normalize().getXCoord().getEncoded());
        hasher.update(aggregatedKey.normalize().getXCoord().getEncoded());

        byte[] digest = hasher.digest(message);
        return new BigInteger(1, digest).mod(curveOrder);
    }

    private BigInteger signPartially(BigInteger secret, BigInteger[] secretNonces, byte[] message, ECPoint coefR, BigInteger challengeE, BigInteger coefA, ECPoint aggKey, BigInteger coefB) {
        BigInteger tmp = null;
        if ( !(coefR.normalize().getYCoord().toBigInteger().mod(TWO).equals(BigInteger.ZERO)) ) {
            for (short i = 0; i < Constants.V; i++) {
                tmp = secretNonces[i];
                secretNonces[i] = curveOrder.subtract(tmp);
            }
        }

        BigInteger partialSig = challengeE;

        // coefA is often 1, but our multiplication is cheap
        partialSig = partialSig.multiply(coefA).mod(curveOrder);
        BigInteger g = BigInteger.ONE;
        if ( !(aggKey.normalize().getYCoord().toBigInteger().mod(TWO).equals(BigInteger.ZERO)) ) {
            // partialSig = curveOrder.subtract(partialSig).mod(curveOrder);
            g = curveOrder.subtract(BigInteger.ONE);
            secret = secret.multiply(g).mod(curveOrder);
        }

        partialSig = partialSig.multiply(secret).mod(curveOrder);
        partialSig = partialSig.add(secretNonces[0]).mod(curveOrder);

        tmp = coefB.multiply(secretNonces[1]).mod(curveOrder);
        partialSig = partialSig.add(tmp).mod(curveOrder);

        return partialSig;
    }

    private boolean isEven(ECPoint point) {
        BigInteger TWO = new BigInteger("2");
        return point.normalize().getYCoord().toBigInteger().mod(TWO) == BigInteger.ZERO;
    }

    private BigInteger sign(BigInteger secret, BigInteger[] secretNonces, byte[] message, ECPoint[] aggNonces, ECPoint aggKey, BigInteger coefA) throws NoSuchAlgorithmException {

        BigInteger coefB = generateCoefB(message, aggNonces, aggKey);

        ECPoint coefR = generateCoefR(coefB, aggNonces);

        BigInteger challengeE = generateChallengeE(message, coefR, aggKey);

        BigInteger partialSig = signPartially(secret, secretNonces, message, coefR, challengeE, coefA, aggKey, coefB);
        return partialSig;
    }

    private byte[] aggregateSignatures(byte[] message, BigInteger[] partialSigs, ECPoint[] aggNonces, ECPoint aggKey) throws Exception {
        BigInteger aggSig = BigInteger.ZERO;


        for (int i = 0; i < partialSigs.length; i++){
            if ( partialSigs[i].compareTo(curveOrder) >= 0 ) {
                throw new IllegalArgumentException();
            }
            aggSig = aggSig.add(partialSigs[i]).mod(curveOrder);
        }

        BigInteger g = curveOrder.subtract(BigInteger.ONE);
        if ( isEven(aggKey) ) {
            g = BigInteger.ONE;
        }

        BigInteger coefB = generateCoefB(message, aggNonces, aggKey);
        ECPoint coefR = generateCoefR(coefB, aggNonces);

        BigInteger challengeE = generateChallengeE(message, coefR, aggKey);

        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        stream.write(coefR.normalize().getXCoord().getEncoded());
        // FIXME the coefA can be less than 32 bytes
        byte[] aggSigBytes = aggSig.toByteArray();
        if ( aggSigBytes.length == 33 && aggSigBytes[0] == (byte) 0x00 ) {
            aggSigBytes = Arrays.copyOfRange(aggSigBytes, 1, 33);
        }
        stream.write(aggSigBytes);
        return stream.toByteArray();
    }

    public Optional<ECPoint> liftX(byte[] bytes) {
        BigInteger x = new BigInteger(1, bytes);
        if ( x.compareTo(fieldPrime) >= 0 ) {
            return Optional.empty();
        };

        BigInteger ySquare = x.modPow(THREE, fieldPrime).add(curveB).add(x.multiply(curveA)).mod(fieldPrime);
        // BigInteger y = pow(y_sq, (p + 1) // 4, p)
        BigInteger y = ySquare.modPow(fieldPrime.add(BigInteger.ONE).divide(FOUR), fieldPrime);

        if ( y.modPow(TWO, fieldPrime).compareTo(ySquare) != 0 ) {
            return Optional.empty();
        }

        if ( y.testBit(0) ) {
            y = fieldPrime.subtract(y);
        }

        return Optional.of(curve.createPoint(x, y));
    }

    public boolean SchnorrVerify(byte[] message, byte[] pubkey, byte[] signature) throws NoSuchAlgorithmException {
        if ( message.length != 32 ) {
            throw new IllegalArgumentException();
        }
        if ( pubkey.length != 32 ) {
            throw new IllegalArgumentException();
        }
        if ( signature.length != 64 ) {
            throw new IllegalArgumentException();
        }
        // P = lift_x(pubkey)
        ECPoint P = curve.getInfinity();
        try {
            P = liftX(pubkey).get();
        } catch (NoSuchElementException e) {
            return false;
        }

        if ( P.isInfinity() ) {
            return false;
        }

        // r = int_from_bytes(sig[0:32])
        byte[] rPart = Arrays.copyOfRange(signature, 0, 32);
        BigInteger r = new BigInteger(1, rPart);

        // s = int_from_bytes(sig[32:64])
        BigInteger s = new BigInteger(1, Arrays.copyOfRange(signature, 32, 64));
        if ( (r.compareTo(fieldPrime) >= 0) || ( s.compareTo(curveOrder) >= 0) ) {
            return false;
        }

        HashCustomTest hasher = new HashCustomTest();
        hasher.init(HashCustom.BIP_CHALLENGE);
        hasher.update(rPart);
        hasher.update(pubkey);
        hasher.update(message);
        BigInteger e = (new BigInteger(1, hasher.digest())).mod(curveOrder);

        ECPoint R = Generator.multiply(s).add(P.multiply(curveOrder.subtract(e)));

        boolean validR = Arrays.equals(R.normalize().getXCoord().getEncoded(), rPart);
        if ( R.isInfinity() || !isEven(R) || !validR ) {
            return false;
        }
        return true;
    }

    private ECPoint getPublic(BigInteger secret) {
        return Generator.multiply(secret);
    }

    public byte[] cbytesExt(ECPoint point) {
        if ( point.isInfinity() ) {
            return new byte[33];
        }
        return point.getEncoded(true);
    }

    private byte[] aggregateNonces(ECPoint[][] publicNonces) throws IOException {
        ByteArrayOutputStream aggNonce = new ByteArrayOutputStream();
        // byte[] aggNonce = null;
        ECPoint R_j = null;
        ECPoint R_ij = null;
        for (int j = 0; j <= 1; j++) {
            R_j = curve.getInfinity();
            for (int i = 0; i < publicNonces.length; i++ ) {
                // = cpoint(pubnonces[i][(j-1)*33:j*33])
                R_ij = publicNonces[i][j];
                R_j = R_j.add(R_ij);
            }
            aggNonce.write(cbytesExt(R_j));
        }

        return aggNonce.toByteArray();
    }

    @Test
    public void testComputePublicTest() throws Exception {
        BigInteger secret = new BigInteger(1, Hex.decode("b1c96b8ab21c6c5e04c64b693491957d027093c58087f9559e757a04428f399d"));
        Assert.assertArrayEquals(getPublic(secret).getEncoded(true), Hex.decode("03f7e64e51389b49417ca5bbb1a87d9a5648486899ec38695e550f060b6eea5cdf"));
    }

    public ECPoint[] getPublicNonces(BigInteger[] secretNonces) {
        ECPoint[] publicNonces = new ECPoint[Constants.V];
        for (int i = 0; i < Constants.V; i++) {
            publicNonces[i] = Generator.multiply(secretNonces[i]);
        }
        return publicNonces;
    }

    /*
     * The card expects the A coefficient encoded as 32 bytes, but BigInteger.toByteArray() uses the least
     * number of bytes required. Thus this helper creates 32 byte array and copies the serialized BigInteger
     * into it.
     */
    private byte[] serializeCoefAForCard(BigInteger coefficient) {
        byte[] out = new byte[32];
        byte[] tmp = coefficient.toByteArray();
        for (int i = 0; i < tmp.length; i++) {
            out[31 - i] = tmp[tmp.length - i - 1];
        }
        return out;
    }

    @Test
    public void testACoefSerialization() {
        byte[] one = new byte[32];
        one[31] = (byte) 0x01;

        Assert.assertArrayEquals(one, serializeCoefAForCard(new BigInteger(one)));

        byte[] more = new byte[32];
        more[30] = (byte) 0x02;
        more[31] = (byte) 0x01;

        Assert.assertArrayEquals(more, serializeCoefAForCard(new BigInteger(more)));

        SecureRandom prng = new SecureRandom(new byte[32]);
        prng.nextBytes(more);

        Assert.assertArrayEquals(more, serializeCoefAForCard(new BigInteger(more)));
    }

    @Test
    public void testMusig2SignatureInternal() throws Exception {
        SecureRandom prng = new SecureRandom(new byte[32]);
        byte[] message = new byte[32];
        prng.nextBytes(message);

        // privateKey
        byte[] secretBytes = new byte[32];
        prng.nextBytes(secretBytes);
        BigInteger testSecret = new BigInteger(1, secretBytes);
        ECPoint testPublicKey = getPublic(testSecret);

        // secnonce
        byte[][] secretNonces = new byte[2][32];
        prng.nextBytes(secretNonces[0]);
        prng.nextBytes(secretNonces[1]);

        BigInteger[] testSecretNonces = new BigInteger[Constants.V];
        testSecretNonces[0] = new BigInteger(1, secretNonces[0]);
        testSecretNonces[1] = new BigInteger(1, secretNonces[1]);
        ECPoint[] testPublicNonces = getPublicNonces(testSecretNonces);

        CommandAPDU cmd = new CommandAPDU(Consts.CLA.INDIE, Consts.INS.GENERATE_KEY_MUSIG2, 0x00, 0);
        ResponseAPDU responseAPDU = connect().transmit(cmd);
        Assert.assertEquals(Consts.SW.OK, (short) responseAPDU.getSW());
        ECPoint cardPublicKey = curve.decodePoint(responseAPDU.getData());

        cmd = new CommandAPDU(Consts.CLA.INDIE, Consts.INS.GENERATE_NONCE_MUSIG2, 0x00, 0);
        responseAPDU = connect().transmit(cmd);
        Assert.assertEquals(Consts.SW.OK, (short) responseAPDU.getSW());

        cmd = new CommandAPDU(Consts.CLA.INDIE, Consts.INS.GET_PUBLIC_NONCE_SHARE, 0x00, 0);
        responseAPDU = connect().transmit(cmd);
        Assert.assertEquals(Consts.SW.OK, (short) responseAPDU.getSW());
        ECPoint[] cardPublicNonces = new ECPoint[Constants.V];
        cardPublicNonces[0] = curve.decodePoint(Arrays.copyOfRange(responseAPDU.getData(), 0, 33));
        cardPublicNonces[1] = curve.decodePoint(Arrays.copyOfRange(responseAPDU.getData(), 33, 66));

        byte[] aggregatedNonces = aggregateNonces(new ECPoint[][] { testPublicNonces, cardPublicNonces });
        ECPoint[] aggregatedNoncesPoints = new ECPoint[Constants.V];
        aggregatedNoncesPoints[0] = curve.decodePoint(Arrays.copyOfRange(aggregatedNonces, 0, 33));
        aggregatedNoncesPoints[1] = curve.decodePoint(Arrays.copyOfRange(aggregatedNonces, 33, 66));

        cmd = new CommandAPDU(Consts.CLA.INDIE, Consts.INS.SET_MUSIG2_AGG_NONCE, 0x00, 0, aggregatedNonces);
        responseAPDU = connect().transmit(cmd);
        Assert.assertEquals(Consts.SW.OK, (short) responseAPDU.getSW());

        // test aggregating public keys
        ECPoint[] keys = new ECPoint[] { testPublicKey, cardPublicKey };
        ECPoint correctAggKey = keyAgg(keys);

        // test A coefs
        BigInteger coefA_0 = keyAggCoeff(keys, keys[0]);
        BigInteger coefA_1 = keyAggCoeff(keys, keys[1]);
        System.out.println("coefA_1");
        System.out.println(Hex.toHexString(coefA_1.toByteArray()));

        BigInteger sig = sign(testSecret, testSecretNonces, message, aggregatedNoncesPoints, correctAggKey, coefA_0);


        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        stream.write(correctAggKey.getEncoded(true));
        stream.write(serializeCoefAForCard(coefA_1));

        // card Sign
        cmd = new CommandAPDU(Consts.CLA.INDIE, Consts.INS.SET_MUSIG2_AGG_KEY, 0x00, 0, stream.toByteArray());
        responseAPDU = connect().transmit(cmd);
        Assert.assertEquals(Consts.SW.OK, (short) responseAPDU.getSW());

        cmd = new CommandAPDU(Consts.CLA.INDIE, Consts.INS.MUSIG2_SIGN, 0x00, 0, message);
        responseAPDU = connect().transmit(cmd);

        Assert.assertEquals(Consts.SW.OK, (short) responseAPDU.getSW());

        BigInteger[] partialSigs = new BigInteger[] { sig, new BigInteger(1, responseAPDU.getData()) };
        byte[] aggregatedSignature = aggregateSignatures(message, partialSigs, aggregatedNoncesPoints, correctAggKey);

        Assert.assertTrue(
            "Signature does not verify",
            SchnorrVerify(message, correctAggKey.normalize().getXCoord().getEncoded(),
            aggregatedSignature)
        );
    }
}
