package tests;

import cz.muni.fi.crocs.rcard.client.CardType;
import applet.IndistinguishabilityApplet;
import applet.Consts;
import org.junit.Assert;
import org.junit.jupiter.api.*;

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
    
    public AppletTest() throws Exception {
        // System.out.println("AppletTest initializing...");
        // Change card type here if you want to use physical card
        setCardType(CardType.JCARDSIMLOCAL);
        setSimulateStateful(true);
        connect();
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

    // @Test
    // public void testFindingDecodedValue() throws Exception {
    //     // String token = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";
    //     String token = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImV4YW1wbGUifQ.eyJpc3MiOiJodHRwczovL2F1dGhsaWIub3JnIiwiYXVkIjpbInprTG9naW4iXSwiaWF0IjoxNzQ1NzczNTI3LCJleHAiOjE3NDU3NzcxMjcsImF1dGhfdGltZSI6MTc0NTc3MzUyNiwibm9uY2UiOiIyNTViZmFhNzk4ZWM0MzQxNjllMmNiOWRiMzNjN2VkNWExYTE2MjE5NmQ4ZTIwNzUxMjE2MGM3NTg1YTJiMTM3IiwiYXRfaGFzaCI6IkU5RnVLX2pTazJ0VGFHWFFRME16WEEiLCJzdWIiOiIxMiIsIm5hbWUiOiJGaXJzdG5hbWUgTGFzdG5hbWUifQ.mv2JmIh2lu0Ucphv1n6Gon6J2AwoM7EwkDjaRqIt_FJ3SYOWQSgUzqernYoq749c2sm9HpAEaGz1_8ohV19j8w";

    //     byte[] byteToken = token.getBytes();
    //     // byte[] slice = Arrays.copyOfRange(byteToken, 0, 127);
    //     // byte[] data = {'d', 'a', 't', 'a'};
    //     CommandAPDU cmd = new CommandAPDU(0x00, 0x02, 0x01, 0, byteToken);
    //     ResponseAPDU responseAPDU = connect().transmit(cmd);
    //     System.out.println(String.format("byteInput length: %d", byteToken.length));
    //     System.out.println(String.format("Received: %d", responseAPDU.getData().length));
    //     System.out.println(String.format("\"%s\"", new String(responseAPDU.getData(), "UTF-8")));
    // }

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

    // @Test
    // public void test2() throws Exception {
    //     String token = "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.DtEhU3ljbEg8L38VWAfUAqOyKAM6-Xx-F4GawxaepmXFCgfTjDxw5djxLa8ISlSApmWQxfKTUJqPP3-Kg6NU1Q";


    // }

    // Example test
    // @Test
    // public void hello() throws Exception {
    //     final byte[] AID = {(byte) 0xF0, 0x00, 0x00, 0x00, 0x01};
    //     final CommandAPDU cmd = new CommandAPDU(0x02, 0x00, 0, 0, AID);

    //     // final byte[] AID = {0x01, (byte) 0xff, (byte) 0xff, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};
    //     // AID appletAID = AIDUtil.create("F000000001");

    //     final CommandAPDU select = new CommandAPDU(0xA4, 0x80, 0, 0);
    //     // System.out.println(cmd);
    //     final ResponseAPDU responseAPDU2 = connect().transmit(select);
    //     String str2 = new String(responseAPDU2.getData(), "UTF-8");
    //     System.out.println(str2);
    //     final ResponseAPDU responseAPDU = connect().transmit(cmd);

    //     // final byte[] expectedResponse = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!'};
    //     Assert.assertNotNull(responseAPDU);
    //     Assert.assertEquals(0x9000, responseAPDU.getSW());
    //     Assert.assertNotNull(responseAPDU.getBytes());

    //     StringBuilder sb = new StringBuilder();
    //     for (byte b : responseAPDU.getData()) {
    //         sb.append(String.format("0x%02X ", b));
    //     }
    //     System.out.println(sb.toString());
    //     // System.out.println(responseAPDU.getBytes());
    //     String str = new String(responseAPDU.getData(), "UTF-8");
    //     System.out.println(str);
    //     // Assert.assertEquals(expectedResponse, responseAPDU.getBytes());
    //     //
    // }
}
