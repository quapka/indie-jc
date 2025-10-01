package tests;

import cz.muni.fi.crocs.rcard.client.CardType;
import applet.IndistinguishabilityApplet;
import applet.Consts;
import applet.jcmathlib;
import org.junit.Assert;
import org.junit.jupiter.api.*;

import applet.jcmathlib.*;
import javacard.security.*;

import java.security.*;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.crypto.*;
import org.bouncycastle.crypto.modes.*;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.crypto.engines.*;
// import org.bouncycastle.crypto.modes.AEADCipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.math.BigInteger;

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
        // Change card type here if you want to use physical card
        // String cardTypeProp = System.getProperty("testcard.type");
        // if ( cardTypeProp == null ) {
        //     cardType = CardType.JCARDSIMLOCAL;
        // } else if ( cardTypeProp == "physical" )  {
        //     cardType = CardType.PHYSICAL;
        // } else if ( cardTypeProp == "simlocal" ) {
        //     cardType = CardType.JCARDSIMLOCAL;
        // }
        // setCardType(CardType.PHYSICAL);

        if ( IndistinguishabilityApplet.CARD_TYPE == jcmathlib.OperationSupport.SIMULATOR ){
            setCardType(CardType.JCARDSIMLOCAL);
        } else {
            setCardType(CardType.PHYSICAL);
        }
        setSimulateStateful(true);
        connect();

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
        // String token = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";
        String token = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImV4YW1wbGUifQ.eyJpc3MiOiJodHRwczovL2F1dGhsaWIub3JnIiwiYXVkIjpbInprTG9naW4iXSwiaWF0IjoxNzQ1NzczNTI3LCJleHAiOjE3NDU3NzcxMjcsImF1dGhfdGltZSI6MTc0NTc3MzUyNiwibm9uY2UiOiIyNTViZmFhNzk4ZWM0MzQxNjllMmNiOWRiMzNjN2VkNWExYTE2MjE5NmQ4ZTIwNzUxMjE2MGM3NTg1YTJiMTM3IiwiYXRfaGFzaCI6IkU5RnVLX2pTazJ0VGFHWFFRME16WEEiLCJzdWIiOiIxMiIsIm5hbWUiOiJGaXJzdG5hbWUgTGFzdG5hbWUifQ.mv2JmIh2lu0Ucphv1n6Gon6J2AwoM7EwkDjaRqIt_FJ3SYOWQSgUzqernYoq749c2sm9HpAEaGz1_8ohV19j8w";

        byte[] byteToken = token.getBytes();
        // byte[] slice = Arrays.copyOfRange(byteToken, 0, 127);
        // byte[] data = {'d', 'a', 't', 'a'};
        CommandAPDU cmd = new CommandAPDU(Consts.CLA.INDIE, 0x02, 0x00, 0, byteToken);
        ResponseAPDU responseAPDU = connect().transmit(cmd);

        System.out.println(String.format("byteInput length: %d", byteToken.length));
        System.out.println(String.format("Received: %d", responseAPDU.getData().length));
        System.out.println(String.format("\"%s\"", new String(responseAPDU.getData(), "UTF-8")));
    }

    @Test
    public void testDerivingSalt() throws Exception {
        // String token = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";
        String token = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImV4YW1wbGUifQ.eyJpc3MiOiJodHRwczovL2F1dGhsaWIub3JnIiwiYXVkIjpbInprTG9naW4iXSwiaWF0IjoxNzQ1NzczNTI3LCJleHAiOjE3NDU3NzcxMjcsImF1dGhfdGltZSI6MTc0NTc3MzUyNiwibm9uY2UiOiIyNTViZmFhNzk4ZWM0MzQxNjllMmNiOWRiMzNjN2VkNWExYTE2MjE5NmQ4ZTIwNzUxMjE2MGM3NTg1YTJiMTM3IiwiYXRfaGFzaCI6IkU5RnVLX2pTazJ0VGFHWFFRME16WEEiLCJzdWIiOiIxMiIsIm5hbWUiOiJGaXJzdG5hbWUgTGFzdG5hbWUifQ.mv2JmIh2lu0Ucphv1n6Gon6J2AwoM7EwkDjaRqIt_FJ3SYOWQSgUzqernYoq749c2sm9HpAEaGz1_8ohV19j8w";
        // String token = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImV4YW1wbGUifQ.eyJpc3MiOiJodHRwczovL2F1dGhsaWIub3JnIiwiYXVkIjpbInprTG9naW4iXSwiaWF0IjoxNzQ1ODI3NzQ0LCJleHAiOjE3NDU4MzEzNDQsImF1dGhfdGltZSI6MTc0NTgyNzc0Mywibm9uY2UiOiI4MDY4YWU4YTMxN2IyMjBmODQ0ZTg1OTczOWE3YTY0YmY1ZGRhNzU5YjEzZmM4MGRjMDllYjIwODM1MWZhY2ViIiwiYXRfaGFzaCI6IjZ0TlFBcXZZVDFGc1BhamJkcFllQmciLCJzdWIiOiIxMiIsIm5hbWUiOiJGaXJzdG5hbWUgTGFzdG5hbWUifQ.i6UOXl1M8Viohu-LPfBFKnCjUCptOF59dXqM8mrHP0hqOIY5Em8XZC8bpoxmy--KW0hn5QjO7_Psx907ZodWuw";

        byte[] byteToken = token.getBytes();
        // byte[] slice = Arrays.copyOfRange(byteToken, 0, 127);
        // byte[] data = {'d', 'a', 't', 'a'};
        System.out.println("Command:");
        CommandAPDU cmd = new CommandAPDU(Consts.CLA.INDIE, 0x03, 0x00, 0, byteToken);

        for (short i = 0; i < cmd.getBytes().length; i++) {
            System.out.print(String.format("%02x", cmd.getBytes()[i]));
        }
        System.out.println("end.");
        ResponseAPDU responseAPDU = connect().transmit(cmd);
        System.out.println(String.format("byteInput length: %d", byteToken.length));
        System.out.println(String.format("Received: %d", responseAPDU.getData().length));
        System.out.println(String.format("\"%s\"", new String(responseAPDU.getData(), "UTF-8")));

        byte[] salt = responseAPDU.getData();

        for (short i = 0; i < salt.length; i++) {
            System.out.print(String.format("%02x", salt[i]));
        }
        System.out.println();
    }

    @Test
    public void testGettingExampleDleqProof() throws Exception {
        String token = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImV4YW1wbGUifQ.eyJpc3MiOiJodHRwczovL2F1dGhsaWIub3JnIiwiYXVkIjpbInprTG9naW4iXSwiaWF0IjoxNzQ1NzczNTI3LCJleHAiOjE3NDU3NzcxMjcsImF1dGhfdGltZSI6MTc0NTc3MzUyNiwibm9uY2UiOiIyNTViZmFhNzk4ZWM0MzQxNjllMmNiOWRiMzNjN2VkNWExYTE2MjE5NmQ4ZTIwNzUxMjE2MGM3NTg1YTJiMTM3IiwiYXRfaGFzaCI6IkU5RnVLX2pTazJ0VGFHWFFRME16WEEiLCJzdWIiOiIxMiIsIm5hbWUiOiJGaXJzdG5hbWUgTGFzdG5hbWUifQ.mv2JmIh2lu0Ucphv1n6Gon6J2AwoM7EwkDjaRqIt_FJ3SYOWQSgUzqernYoq749c2sm9HpAEaGz1_8ohV19j8w";
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

    @Test
    public void testDLEQAgainstGeneratedKey() throws Exception {
        CommandAPDU cmd = new CommandAPDU(Consts.CLA.INDIE, Consts.INS.KEY_GEN, 0x00, 0);
        ResponseAPDU responseAPDU = connect().transmit(cmd);
        byte[] data = responseAPDU.getData();

        BigInteger xCoord = new BigInteger(SIGNUM_POSITIVE, Arrays.copyOfRange(data, 1, 33));
        BigInteger yCoord = new BigInteger(SIGNUM_POSITIVE, Arrays.copyOfRange(data, 35, 65));
        ECPoint dvrfPubKey = curve.createPoint(xCoord, yCoord);
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
    public void testAuthenticatedDecrytion() throws Exception {
        CommandAPDU cmd = new CommandAPDU(Consts.CLA.INDIE, Consts.INS.KEY_GEN, 0x00, 0);
        ResponseAPDU responseAPDU = connect().transmit(cmd);
        byte[] data = responseAPDU.getData();

        BigInteger xCoord = new BigInteger(SIGNUM_POSITIVE, Arrays.copyOfRange(data, 1, 33));
        BigInteger yCoord = new BigInteger(SIGNUM_POSITIVE, Arrays.copyOfRange(data, 35, 65));
        ECPoint dvrfPubKey = curve.createPoint(xCoord, yCoord);


        // FIXME use ECDH derive shared secret
        byte[] emptyKey = new byte[16];
        byte[] emptyNonce = new byte[12];

        KeyParameter aeadKey = new KeyParameter(emptyKey, 0, 16);
        short macSizeBits = 128;
        AEADParameters params = new AEADParameters(aeadKey, macSizeBits, emptyNonce);

        // printBuffer(params.getNonce(), (short) 16);

        System.out.println(params.getMacSize());
        AEADCipher cipher = new GCMBlockCipher(new AESEngine());

        boolean forEncryption = true;
        cipher.init(forEncryption, params);
        byte[] ctxtBuff = new byte[256];

        String message = "this is my message";
        byte[] msgBytes = message.getBytes();

        int read = cipher.processBytes(msgBytes, 0, msgBytes.length, ctxtBuff, 0);
        read += cipher.doFinal(ctxtBuff, read);
        System.out.println("Calculated ciphertext.");
        printBuffer(ctxtBuff, (short) read);


        cmd = new CommandAPDU(Consts.CLA.DEBUG, Consts.INS.AEAD_DECRYPT, (byte) read, 0x00, ctxtBuff, 0, read);
        responseAPDU = connect().transmit(cmd);

        System.out.println(String.format("Plaintext: \"%s\"", new String(responseAPDU.getData(), "UTF-8")));

        Assert.assertTrue(Arrays.equals(msgBytes, responseAPDU.getData()));
    }
}
