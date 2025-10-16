package tests;

import cz.muni.fi.crocs.rcard.client.CardType;
import applet.IndistinguishabilityApplet;
import applet.Consts;
import applet.jcmathlib;
import org.junit.Assert;
import org.junit.jupiter.api.*;

import applet.jcmathlib.*;
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

// import java.util.HashMap;
// import java.util.Map;
// import com.fasterxml.jackson.databind.ObjectMapper;


import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import java.util.Arrays;

/**
 * Example test class for the applet
 * Note: If simulator cannot be started try adding "-noverify" JVM parameter
 *
 * @author xsvenda, Dusan Klinec (ph4r05)
 */
public class AppletTest extends BaseTest {
    public static ECCurve curve;
    public static ECPoint Generator;
    public static BigInteger x;
    public static BigInteger y;
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
        Assert.assertTrue(Arrays.equals(IndistinguishabilityApplet.Good, responseAPDU.getData()));
    }

    @Test
    public void testDebugBad() throws Exception {
        CommandAPDU cmd = new CommandAPDU(Consts.CLA.DEBUG, Consts.INS.BAD, 0, 0);
        ResponseAPDU responseAPDU = connect().transmit(cmd);

        Assert.assertEquals(Consts.SW.OK, (short) responseAPDU.getSW());
        Assert.assertTrue(Arrays.equals(IndistinguishabilityApplet.Bad, responseAPDU.getData()));
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
        payload += "\"nonce\":\"" + Hex.toHexString(nonce) + "\",";
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

        KeyFactory keyFact = KeyFactory.getInstance("ECDH", "BC");
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

        Assert.assertTrue(Arrays.equals(msgBytes, responseAPDU.getData()));
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
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDH", "BC");
        ECGenParameterSpec ecGenSpec = new ECGenParameterSpec("secP256r1");
        kpg.initialize(ecGenSpec, new SecureRandom());
        KeyPair keyPair = kpg.generateKeyPair();
        ECPublicKey pubKey = (ECPublicKey) keyPair.getPublic();

        // TODO does sending compressed point speed up the operations?
        // Need to consider also the uncompressing inside the card.
        KeyFactory keyFact = KeyFactory.getInstance("ECDH", "BC");
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
        Assert.assertTrue(Arrays.equals(IndistinguishabilityApplet.Good, responseAPDU.getData()));
    }

    @Test
    public void testSetOIDCPublicKey() throws Exception {
        SignatureAlgorithm alg = Jwts.SIG.ES256;
        KeyPair pair = alg.keyPair().build();

        KeyFactory keyFact = KeyFactory.getInstance("ECDH", "BC");
        ECPublicKeySpec pubSpec = keyFact.getKeySpec(pair.getPublic(), ECPublicKeySpec.class);
        boolean compressed = false;
        // FIXME use compressed to speed up processing and shorten data payloads?
        byte[] uncompressedPubKey = pubSpec.getQ().getEncoded(compressed);

        // Set and implicitly get the public key
        CommandAPDU cmd = new CommandAPDU(Consts.CLA.INDIE, Consts.INS.SET_OIDC_PUBKEY, 0x00, 0x00, uncompressedPubKey);
        ResponseAPDU responseAPDU = connect().transmit(cmd);

        Assert.assertEquals(Consts.SW.OK, (short) responseAPDU.getSW());
        Assert.assertTrue(Arrays.equals(uncompressedPubKey, responseAPDU.getData()));

        // Explicitly get the public key again
        cmd = new CommandAPDU(Consts.CLA.INDIE, Consts.INS.GET_OIDC_PUBKEY, 0x00, 0x00);
        responseAPDU = connect().transmit(cmd);

        Assert.assertEquals(Consts.SW.OK, (short) responseAPDU.getSW());
        Assert.assertTrue(Arrays.equals(uncompressedPubKey, responseAPDU.getData()));
    }

    @Test
    public void testJWTVerification() throws Exception {
        SignatureAlgorithm alg = Jwts.SIG.ES256;
        KeyPair pair = alg.keyPair().build();

        KeyFactory keyFact = KeyFactory.getInstance("ECDH", "BC");
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

        cmd = new CommandAPDU(Consts.CLA.DEBUG, Consts.INS.VERIFY_JWT, 0x00, 0x00, jwt.getBytes());
        responseAPDU = connect().transmit(cmd);

        Assert.assertEquals(Consts.SW.OK, (short) responseAPDU.getSW());
        Assert.assertTrue(Arrays.equals(IndistinguishabilityApplet.Good, responseAPDU.getData()));
    }
}
