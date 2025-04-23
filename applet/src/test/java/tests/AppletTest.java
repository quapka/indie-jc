package tests;

import cz.muni.fi.crocs.rcard.client.CardType;
import org.junit.Assert;
import org.junit.jupiter.api.*;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

/**
 * Example test class for the applet
 * Note: If simulator cannot be started try adding "-noverify" JVM parameter
 *
 * @author xsvenda, Dusan Klinec (ph4r05)
 */
public class AppletTest extends BaseTest {
    
    public AppletTest() {
        // Change card type here if you want to use physical card
        setCardType(CardType.JCARDSIMLOCAL);
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
    public void test() throws Exception {


        CommandAPDU cmd = new CommandAPDU(0x04, 0x00, 0, 0);
        ResponseAPDU responseAPDU = connect().transmit(cmd);
        System.out.println(new String(responseAPDU.getData(), "UTF-8"));

        cmd = new CommandAPDU(0x02, 0x00, 0, 0);
        responseAPDU = connect().transmit(cmd);
        System.out.println(new String(responseAPDU.getData(), "UTF-8"));
    }

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
