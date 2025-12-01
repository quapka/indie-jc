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

        Assert.assertEquals(Consts.SW.OK, (short) responseAPDU.getSW());

        cmd = new CommandAPDU(Consts.CLA.INDIE, Consts.INS.GENERATE_NONCE_MUSIG2, 0x00, 0);
        responseAPDU = connect().transmit(cmd);

        Assert.assertEquals(Consts.SW.OK, (short) responseAPDU.getSW());

        cmd = new CommandAPDU(Consts.CLA.INDIE, Consts.INS.GET_PUBLIC_NONCE_SHARE, 0x00, 0);
        responseAPDU = connect().transmit(cmd);

        Assert.assertEquals(Consts.SW.OK, (short) responseAPDU.getSW());
        Assert.assertEquals(Constants.XCORD_LEN * Constants.V, (short) responseAPDU.getData().length);
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

    // FIXME add tagged hash functions
    public BigInteger getACoeff(ECPoint[] pubkeys, ECPoint current_key) throws NoSuchAlgorithmException {
        HashCustomTest hasher = new HashCustomTest();
        hasher.init("KeyAgg list");

        hasher.update(current_key.getEncoded(true));
        for(int i = 0; i < pubkeys.length; i++) {
            hasher.update(pubkeys[i].getEncoded(true));
        }
        // The BIP-0327 uses another tagger hashing
        byte[] digest = hasher.digest();
        BigInteger inte = (new BigInteger(digest)).mod(curveOrder);
        return inte;
    }

    public ECPoint aggregateKeys(ECPoint[] pubkeys) throws NoSuchAlgorithmException {
        ECPoint aggregatedKey = curve.getInfinity();
        for (int i = 0; i < pubkeys.length; i++)  {
             aggregatedKey = aggregatedKey.add(pubkeys[i].multiply(getACoeff(pubkeys, pubkeys[i])));
        }

        return aggregatedKey;
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
        // .fromByteArray(tmpArray, (short) 0, Constants.HASH_LEN);
        // coefB.mod(CURVE_R);
        return coefB;
    }

    private ECPoint generateCoefR(BigInteger coefB, ECPoint[] aggNonces) {
        return aggNonces[1].multiply(coefB).add(aggNonces[0]);
    }

    private BigInteger generateChallengeE(byte[] message, ECPoint coefR, ECPoint aggregatedKey) throws NoSuchAlgorithmException {
        HashCustomTest hasher = new HashCustomTest();
        hasher.init(HashCustom.BIP_CHALLENGE);

        hasher.update(coefR.normalize().getXCoord().getEncoded());
        // hasher.update(Arrays.copyOfRange(coefR.getEncoded(true), 1, 33));
        hasher.update(aggregatedKey.normalize().getXCoord().getEncoded());
        // hasher.update(Arrays.copyOfRange(aggregatedKey.getEncoded(true), 1, 33));

        byte[] digest = hasher.digest(message);
        // System.out.println("digest E");
        // System.out.println(Hex.toHexString((new BigInteger(Hex.decode("cbacf3658e7a22467b1061819c1d494523980e8b499bc4906033cfd15128a471")).mod(curveOrder).toByteArray())));
        // System.out.println(Hex.toHexString(curveOrder.toByteArray()));
        BigInteger E = new BigInteger(1, digest).mod(curveOrder);
        // Assert.assertEquals("E does not have the expected byte-length 32", 32, E.toByteArray().length);
        // System.out.println(Hex.toHexString(curveOrder.toByteArray()));
        // System.out.println(Hex.toHexString(new BigInteger(Hex.toHexString(curveOrder.toByteArray()), 16).toByteArray()));
        // Assert.assertEquals("curveOrder does not have the expected byte-length 32", 32, curveOrder.toByteArray().length);
        return E;
        // return (new BigInteger(1, hasher.digest(message))).mod(curveOrder);
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

    private BigInteger sign(BigInteger secret, BigInteger[] secretNonces, byte[] message, ECPoint[] aggNonces, ECPoint aggKey, BigInteger coefA, byte[] expCoefB, byte[] expCoefR, byte[] expChallE) throws NoSuchAlgorithmException {

        BigInteger coefB = generateCoefB(message, aggNonces, aggKey);
        Assert.assertArrayEquals("Coef B does not match", expCoefB, coefB.toByteArray());

        ECPoint coefR = generateCoefR(coefB, aggNonces);
        Assert.assertArrayEquals("Coef R does not match", expCoefR, coefR.getEncoded(true));

        BigInteger challengeE = generateChallengeE(message, coefR, aggKey);
        // System.out.println(Hex.toHexString(challengeE.toByteArray()));
        Assert.assertTrue("Challenge E does not match", new BigInteger(1, expChallE).equals(challengeE));

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
        // partial_sig_agg: sum partial: 17dd05dbc65d31978d724192a452f894cf724b4c0597b874d7bbf41caba4261e
        Assert.assertTrue("Partial sigs sum does not match", new BigInteger(1, Hex.decode("17dd05dbc65d31978d724192a452f894cf724b4c0597b874d7bbf41caba4261e")).equals(aggSig));

        BigInteger g = curveOrder.subtract(BigInteger.ONE);
        // BigInteger g = new BigInteger(-1, new byte[]{0x01});
        if ( isEven(aggKey) ) {
            g = BigInteger.ONE;
        }
        // partial_sig_agg: g: ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550
        Assert.assertTrue("G's don't match", new BigInteger(1, Hex.decode("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550")).equals(g.mod(curveOrder)));

        BigInteger coefB = generateCoefB(message, aggNonces, aggKey);
        ECPoint coefR = generateCoefR(coefB, aggNonces);
        // partial_sig_agg: R: eb442e2e9a2d69a2df7ec5dc349eb7c88db74f9a2755ad0a0654d84f4eb6ff25
        Assert.assertArrayEquals("R's don't match", Hex.decode("eb442e2e9a2d69a2df7ec5dc349eb7c88db74f9a2755ad0a0654d84f4eb6ff25"), coefR.normalize().getXCoord().getEncoded());

        BigInteger challengeE = generateChallengeE(message, coefR, aggKey);
        // partial_sig_agg: e: cbacf3658e7a22467b1061819c1d494523980e8b499bc4906033cfd15128a471
        Assert.assertTrue("E's don't match", new BigInteger(1, Hex.decode("cbacf3658e7a22467b1061819c1d494523980e8b499bc4906033cfd15128a471")).equals(challengeE));

        // 34530c997185ddba84ef9e7e63e2b6ba994eec225d7bd9f49385faf1ab3a80e0
        Assert.assertTrue("(e * g ) % n does not match", new BigInteger(1, Hex.decode("34530c997185ddba84ef9e7e63e2b6ba994eec225d7bd9f49385faf1ab3a80e0")).equals(challengeE.multiply(g).mod(curveOrder)));

        // partial_sig_agg: (s + e * g) % n: 4c30127537e30f521261e0110835af4f68c1376e631392696b41ef0e56dea6fe
        Assert.assertTrue(
            "(s + e * g ) % n does not match",
            new BigInteger(1, Hex.decode("4c30127537e30f521261e0110835af4f68c1376e631392696b41ef0e56dea6fe"))
                .equals(
                    (aggSig.add(challengeE.multiply(g)).mod(curveOrder))
                )
        );

        // aggSig = (aggSig.add(challengeE.multiply(g))).mod(curveOrder);

        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        stream.write(coefR.normalize().getXCoord().getEncoded());
        // FIXME the coefA can be less than 32 bytes
        stream.write(aggSig.toByteArray());
        byte[] signature = stream.toByteArray();

        return signature;
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

        // e = int_from_bytes(tagged_hash("BIP0340/challenge", sig[0:32] + pubkey + msg)) % n
        HashCustomTest hasher = new HashCustomTest();
        hasher.init("BIP0340/challenge");
        hasher.update(rPart);
        hasher.update(pubkey);
        hasher.update(message);
        BigInteger e = (new BigInteger(1, hasher.digest())).mod(curveOrder);

        // R = point_add(point_mul(G, s), point_mul(P, n - e))
        ECPoint R = null;
        R = Generator.multiply(s).add(P.multiply(curveOrder.subtract(e)));

        // if (R is None) or (not has_even_y(R)) or (x(R) != r);
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
         byte[] aggnonce = Hex.decode("020766F9AF190058191344AA2DF83EF2DAE2E79572814ABDD884CA5DCBB225B91502DDB9FEB4011D74411962F36C99C490EB77DC64503C7B3B7A1B2E10DBE0A3E917");
         byte[] aggregatePublicKeyTest = Hex.decode("0344B6CB4BBD8B6C0A9F9C768F32CA5DF827177BFBC0F218843A7C4BEBFCD24EC5");
         BigInteger coef_a_0 = new BigInteger("23603501198787295439580993970698567818946970708771452188531545428466868805564", 10);
         BigInteger coef_a_1 = new BigInteger("1", 10);
         byte[] partial_sig_0 = Hex.decode("ea5977811ab56cd2626b282a8a318fa143ad3f42463267a9b1e5645ea590cb6f");
         byte[] partial_sig_1 = Hex.decode("2D838E59ABA7C4C62B0719681A2168F348AC06B7667CEF5019905A8102768000");
         // D88DAD25CF239B28396F0A0059D965490B3E70A79EBA46AD41D65C13B1B6E328
         byte[] pk_0 = Hex.decode("0383e5c3028a3ed2c7288bf8ce9f1bbdaf73fb1b41c1dc888f539b31448b000e5a");
         byte[] pk_1 = Hex.decode("03f7e64e51389b49417ca5bbb1a87d9a5648486899ec38695e550f060b6eea5cdf");
         byte[] secret_nonce_0 = Hex.decode("6da5107d6cb154b9f36a7c638883fc16e95091807b0e7978ae463a0ef22f834e149dba8073d0fd601ef54b346d7082264bf220215a17c3902a4f7c8da3225ab30383e5c3028a3ed2c7288bf8ce9f1bbdaf73fb1b41c1dc888f539b31448b000e5a");
         byte[] secret_nonce_1 = Hex.decode("90333a55e850182454283162d363741efae4e456796e876fd30280e3e9b1f6bd11b43b8c3b0f68b377e433ae68b1b1125043a021031eb47f27e7b62b8b6b8abd03f7e64e51389b49417ca5bbb1a87d9a5648486899ec38695e550f060b6eea5cdf");
         byte[] signature = Hex.decode("eb442e2e9a2d69a2df7ec5dc349eb7c88db74f9a2755ad0a0654d84f4eb6ff2517dd05dbc65d31978d724192a452f894cf724b4c0597b874d7bbf41caba4261e");
         byte[] sk_0 = Hex.decode("fa0d0cec500fa8d88d512be3fcfb65ada453367330834efb6bfcf4d5c1cf0159");
         byte[] sk_1 = Hex.decode("b1c96b8ab21c6c5e04c64b693491957d027093c58087f9559e757a04428f399d");
         byte[] public_nonce_0 = Hex.decode("0379d07a0d0c3ffba26ff9a57a60e1b3c4d86451ea1ede1f737f76cb6bd6a07dd3035a7fca18cff6f5e100c0dc4f2763fbcfffff23424cca2575bc160ad8f2aa4580");
         byte[] public_nonce_1 = Hex.decode("03ffd3c1aaa4f9c8dd1b311357ae19e043d897488c2cfdccde87d55549088f61390334e621d5e5c50e5c3c04725c5d88d8b29c67bfa3371ee5ad407fac24eb62a843");
         // 022B495A9B4142DC317624626AD108D4896C12A97AF1A1372E9A7B0F29ADCAEB49022B495A9B4142DC317624626AD108D4896C12A97AF1A1372E9A7B0F29ADCAEB49
        byte[] R_0 = Hex.decode("02EB442E2E9A2D69A2DF7EC5DC349EB7C88DB74F9A2755AD0A0654D84F4EB6FF25");
        byte[] R_1 = Hex.decode("02eb442e2e9a2d69a2df7ec5dc349eb7c88db74f9a2755ad0a0654d84f4eb6ff25");
        byte[] b_0 = Hex.decode("245F3741E5AB1D192C0694C57B3FEA8D5468F0FA2DE8D7B01824DB80FAC58ABC");
        byte[] b_1 = Hex.decode("245F3741E5AB1D192C0694C57B3FEA8D5468F0FA2DE8D7B01824DB80FAC58ABC");
        byte[] e_0 = Hex.decode("cbacf3658e7a22467b1061819c1d494523980e8b499bc4906033cfd15128a471");
        byte[] e_1 = Hex.decode("CBACF3658E7A22467B1061819C1D494523980E8B499BC4906033CFD15128A471");
        // CBACF3658E7A22467B1061819C1D494523980E8B499BC4906033CFD15128A471
        // 02EB442E2E9A2D69A2DF7EC5DC349EB7C88DB74F9A2755AD0A0654D84F4EB6FF25
        // 3C582EC9F21242070A96ED6238DC36DB10153069D768F26301ED17DC645E0CB8

        byte[] message = new byte[32];

        // # privateKey
        BigInteger testSecret = new BigInteger(1, sk_0);
        ECPoint testPublicKey = getPublic(testSecret);
        Assert.assertArrayEquals(pk_0, testPublicKey.getEncoded(true));

        BigInteger cardSecret = new BigInteger(1, sk_1);
        ECPoint cardPublicKey = getPublic(cardSecret);
        Assert.assertArrayEquals(pk_1, cardPublicKey.getEncoded(true));

        // # secnonce
        BigInteger[] testSecretNonces = new BigInteger[Constants.V];
        byte[] first = Arrays.copyOfRange(secret_nonce_0, 0, 32);
        byte[] second = Arrays.copyOfRange(secret_nonce_0, 32, 64);
        System.out.println(Hex.toHexString(first));
        System.out.println(Hex.toHexString(second));
        System.out.println(Hex.toHexString(secret_nonce_0));
        testSecretNonces[0] = new BigInteger(1, first);
        testSecretNonces[1] = new BigInteger(1, second);
        ECPoint[] testPublicNonces = getPublicNonces(testSecretNonces);

        ByteArrayOutputStream st = new ByteArrayOutputStream();
        st.write(testPublicNonces[0].getEncoded(true));
        st.write(testPublicNonces[1].getEncoded(true));
        // System.out.println(Hex.toHexString(st.toByteArray()));
        // System.out.println(Hex.toHexString(public_nonce_0));
        // System.out.println(Hex.toHexString(public_nonce_1));
        Assert.assertArrayEquals(st.toByteArray(), public_nonce_0);

        // # 
        BigInteger[] cardSecretNonces = new BigInteger[Constants.V];
        cardSecretNonces[0] = new BigInteger(1, Arrays.copyOfRange(secret_nonce_1, 0, 32));
        cardSecretNonces[1] = new BigInteger(1, Arrays.copyOfRange(secret_nonce_1, 32, 64));
        ECPoint[] cardPublicNonces = getPublicNonces(cardSecretNonces);

        byte[] aggregatedNonces = aggregateNonces(new ECPoint[][] { testPublicNonces, cardPublicNonces });
        ECPoint[] aggregatedNoncesPoints = new ECPoint[Constants.V];
        aggregatedNoncesPoints[0] = curve.decodePoint(Arrays.copyOfRange(aggregatedNonces, 0, 33));
        aggregatedNoncesPoints[1] = curve.decodePoint(Arrays.copyOfRange(aggregatedNonces, 33, 66));

        Assert.assertArrayEquals(aggnonce, aggregatedNonces);

        ByteArrayOutputStream testDataPayload = new ByteArrayOutputStream();
        testDataPayload.write(new byte[] { Constants.STATE_TRUE, Constants.STATE_TRUE, Constants.STATE_TRUE, Constants.STATE_TRUE, Constants.STATE_TRUE });
        testDataPayload.write(sk_1);
        testDataPayload.write(pk_1);
        testDataPayload.write(aggregatePublicKeyTest);
        testDataPayload.write(aggregatedNonces);
        testDataPayload.write(secret_nonce_1);

        // set test data on card and invoke nonces
        CommandAPDU cmd = new CommandAPDU(Consts.CLA.DEBUG, Consts.INS.SETUP_TEST_DATA, 0x00, 0, testDataPayload.toByteArray());
        ResponseAPDU responseAPDU = connect().transmit(cmd);
        Assert.assertEquals(Consts.SW.OK, (short) responseAPDU.getSW());

        cmd = new CommandAPDU(Consts.CLA.INDIE, Consts.INS.GENERATE_NONCE_MUSIG2, 0x00, 0);
        responseAPDU = connect().transmit(cmd);
        Assert.assertEquals(Consts.SW.OK, (short) responseAPDU.getSW());

        cmd = new CommandAPDU(Consts.CLA.INDIE, Consts.INS.GET_PUBLIC_NONCE_SHARE, 0x00, 0);
        responseAPDU = connect().transmit(cmd);
        Assert.assertEquals(Consts.SW.OK, (short) responseAPDU.getSW());
        Assert.assertArrayEquals(public_nonce_1, responseAPDU.getData());

        Assert.assertArrayEquals(pk_0, testPublicKey.getEncoded(true));
        Assert.assertArrayEquals(pk_1, cardPublicKey.getEncoded(true));
        // test aggregating public keys
        ECPoint[] keys = new ECPoint[] { testPublicKey, cardPublicKey };
        byte[] myKey = aggregateKeys(keys).getEncoded(true);
        ECPoint correctAggKey = keyAgg(keys);

        Assert.assertArrayEquals(aggregatePublicKeyTest, correctAggKey.getEncoded(true));

        // test A coefs
        BigInteger coefA_0 = keyAggCoeff(keys, keys[0]);
        BigInteger coefA_1 = keyAggCoeff(keys, keys[1]);
        System.out.println("coefA_1");
        System.out.println(Hex.toHexString(coefA_1.toByteArray()));

        BigInteger sig = sign(testSecret, testSecretNonces, message, aggregatedNoncesPoints, correctAggKey, coefA_0, b_0, R_0, e_0);
        Assert.assertTrue("Test partial signature does not match", sig.equals(new BigInteger(1, partial_sig_0)));


        ByteArrayOutputStream stream = new ByteArrayOutputStream();
        stream.write(correctAggKey.getEncoded(true));
        stream.write(serializeCoefAForCard(coefA_1));

        // card Sign
        // sendCorrectApdu(Constants.INS_SET_AGG_PUBKEY, firstRoundData.get(i));
        cmd = new CommandAPDU(Consts.CLA.INDIE, Consts.INS.SET_MUSIG2_AGG_KEY, 0x00, 0, stream.toByteArray());
        responseAPDU = connect().transmit(cmd);
        Assert.assertEquals(Consts.SW.OK, (short) responseAPDU.getSW());

        cmd = new CommandAPDU(Consts.CLA.INDIE, Consts.INS.SIGN_NEXT_EPOCH_MUSIG2, 0x00, 0, message);
        responseAPDU = connect().transmit(cmd);

        Assert.assertEquals(Consts.SW.OK, (short) responseAPDU.getSW());
        // System.out.println("Partial signature from card and the expected one");
        // System.out.println(Hex.toHexString(responseAPDU.getData()));
        // System.out.println(Hex.toHexString(partial_sig_1));
        Assert.assertArrayEquals("Card partial signature does not match", partial_sig_1, responseAPDU.getData());

        BigInteger[] partialSigs = new BigInteger[] { sig, new BigInteger(1, responseAPDU.getData()) };
        byte[] aggSig = aggregateSignatures(message, partialSigs, aggregatedNoncesPoints, correctAggKey);

        System.out.println(Hex.toHexString(aggSig));
        System.out.println(Hex.toHexString(signature));
        Assert.assertArrayEquals("Aggregated signatures don't match", aggSig, signature);

        System.out.println(Hex.toHexString(aggSig));
        System.out.println(Hex.toHexString(correctAggKey.getEncoded(true)));
        System.out.println(Hex.toHexString(message));

        Assert.assertTrue("Signature does not verify", SchnorrVerify(message, correctAggKey.normalize().getXCoord().getEncoded(), signature));
    }

    // @Test
    // public void testMusig2Signature() throws Exception {
    //     // generate data to sign
    //     byte[] message = new byte[32];

    //     // "generate" secret and public key
    //     byte[] secretBytes = Hex.decode("931c495d1d390e13b46943163301b1f2bc4bc6ffada7edf091744958e8f8bd88");
    //     BigInteger secret = new BigInteger(1, secretBytes);
    //     ECPoint publicKey = getPublic(secret);

    //     // get card public key
    //     CommandAPDU cmd = new CommandAPDU(Consts.CLA.INDIE, Consts.INS.GENERATE_KEY_MUSIG2, 0x00, 0);
    //     System.out.println("testMusig2Signature 0");
    //     ResponseAPDU responseAPDU = connect().transmit(cmd);
    //     ECPoint cardPublicKey = curve.decodePoint(responseAPDU.getData());
    //     Assert.assertEquals(Consts.SW.OK, (short) responseAPDU.getSW());

    //     // aggregate public keys and set them to card
    //     ECPoint[] keys = new ECPoint[] { publicKey, cardPublicKey };
    //     ECPoint aggregatedKey = aggregateKeys(keys);
    //     BigInteger coefA = getACoeff(keys, cardPublicKey);

    //     ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
    //     outputStream.write(aggregatedKey.getEncoded(true));
    //     // FIXME the coefA can be less than 32 bytes
    //     outputStream.write(coefA.toByteArray());
    //     byte payload[] = outputStream.toByteArray();

    //     System.out.println(String.format("aggregatedKey length: %d", aggregatedKey.getEncoded(true).length));
    //     System.out.println(String.format("coefA length: %d", coefA.toByteArray().length));
    //     System.out.println(String.format("payload length: %d", payload.length));

    //     cmd = new CommandAPDU(Consts.CLA.INDIE, Consts.INS.SET_MUSIG2_AGG_KEY, 0, 0, payload);
    //     responseAPDU = connect().transmit(cmd);
    //     System.out.println("testMusig2Signature 1");
    //     Assert.assertEquals(Consts.SW.OK, (short) responseAPDU.getSW());

    //     // generate nonce
    //     byte[] seed = new byte[32];
    //     SecureRandom prng = new SecureRandom(seed);

    //     BigInteger[] secretNonces = new BigInteger[Constants.V];
    //     for (int i = 0; i < Constants.V; i++) {
    //         byte[] tmp = new byte[32];
    //         prng.nextBytes(tmp);
    //         secretNonces[i] = new BigInteger(1, tmp);
    //     }

    //     ECPoint[] publicNonces = new ECPoint[Constants.V];
    //     for (int i = 0; i < Constants.V; i++) {
    //         publicNonces[i] = Generator.multiply(secretNonces[i]);
    //     }

    //     // get nonce from card
    //     cmd = new CommandAPDU(Consts.CLA.INDIE, Consts.INS.GENERATE_NONCE_MUSIG2, 0, 0);
    //     responseAPDU = connect().transmit(cmd);
    //     System.out.println("2");
    //     Assert.assertEquals(Consts.SW.OK, (short) responseAPDU.getSW());

    //     cmd = new CommandAPDU(Consts.CLA.INDIE, Consts.INS.GET_PUBLIC_NONCE_SHARE, 0, 0);
    //     responseAPDU = connect().transmit(cmd);
    //     System.out.println("3");
    //     Assert.assertEquals(Consts.SW.OK, (short) responseAPDU.getSW());

    //     ECPoint[] cardPublicNonces = new ECPoint[Constants.V];
    //     byte[] encodedCardNonceOne = new byte[33];
    //     byte[] encodedCardNonceTwo = new byte[33];
    //     System.arraycopy(responseAPDU.getData(), 0, encodedCardNonceOne, 0, 33);
    //     System.arraycopy(responseAPDU.getData(), 33, encodedCardNonceTwo, 0, 33);

    //     cardPublicNonces[0] = curve.decodePoint(encodedCardNonceOne);
    //     cardPublicNonces[1] = curve.decodePoint(encodedCardNonceTwo);

    //     // aggregate nonces and set them to card
    //     ECPoint[] aggregatedNonces = new ECPoint[Constants.V];
    //     aggregatedNonces[0] = publicNonces[0].add(cardPublicNonces[0]);
    //     aggregatedNonces[1] = publicNonces[1].add(cardPublicNonces[1]);

    //     outputStream.reset();
    //     outputStream.write(aggregatedNonces[0].getEncoded(true));
    //     outputStream.write(aggregatedNonces[1].getEncoded(true));
    //     payload = outputStream.toByteArray();
    //     System.out.println(Hex.toHexString(payload));

    //     cmd = new CommandAPDU(Consts.CLA.INDIE, Consts.INS.SET_MUSIG2_AGG_NONCE, 0, 0, payload);
    //     responseAPDU = connect().transmit(cmd);
    //     System.out.println("4");
    //     Assert.assertEquals(Consts.SW.OK, (short) responseAPDU.getSW());
        
    //     // sign
    //     BigInteger partialSig = sign(secret, secretNonces, message, aggregatedNonces, aggregatedKey, coefA);

    //     // signPartial on card and get the result
    //     cmd = new CommandAPDU(Consts.CLA.INDIE, Consts.INS.SIGN_NEXT_EPOCH_MUSIG2, 0, 0, message); 
    //     responseAPDU = connect().transmit(cmd);

    //     BigInteger cardPartialSig = new BigInteger(responseAPDU.getData());
    //     BigInteger[] partialSigs = new BigInteger[] {partialSig, cardPartialSig };

    //     byte[] sig = aggregateSignatures(message, partialSigs, aggregatedNonces, aggregatedKey);
    //     System.out.println("Signature:");
    //     System.out.println(Hex.toHexString(sig));
    //     System.out.println("Pubkey:");
    //     System.out.println(Hex.toHexString(aggregatedKey.normalize()getXCoord().getEncoded()));

    //     Assert.assertEquals(Consts.SW.OK, (short) responseAPDU.getSW());
    // }


}
