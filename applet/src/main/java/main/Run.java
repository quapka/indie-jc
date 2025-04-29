package main;

import applet.IndistinguishabilityApplet;
import com.licel.jcardsim.smartcardio.CardSimulator;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javax.smartcardio.*;

public class Run {
    public static void main(String[] args){
        // 1. create simulator
        CardSimulator simulator = new CardSimulator();

        // 2. install applet
        AID appletAID = AIDUtil.create("F000000001");
        simulator.installApplet(appletAID, IndistinguishabilityApplet.class);

        // 3. select applet
        simulator.selectApplet(appletAID);

        // 4. send APDU
        String token = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImV4YW1wbGUifQ.eyJpc3MiOiJodHRwczovL2F1dGhsaWIub3JnIiwiYXVkIjpbInprTG9naW4iXSwiaWF0IjoxNzQ1NzczNTI3LCJleHAiOjE3NDU3NzcxMjcsImF1dGhfdGltZSI6MTc0NTc3MzUyNiwibm9uY2UiOiIyNTViZmFhNzk4ZWM0MzQxNjllMmNiOWRiMzNjN2VkNWExYTE2MjE5NmQ4ZTIwNzUxMjE2MGM3NTg1YTJiMTM3IiwiYXRfaGFzaCI6IkU5RnVLX2pTazJ0VGFHWFFRME16WEEiLCJzdWIiOiIxMiIsIm5hbWUiOiJGaXJzdG5hbWUgTGFzdG5hbWUifQ.mv2JmIh2lu0Ucphv1n6Gon6J2AwoM7EwkDjaRqIt_FJ3SYOWQSgUzqernYoq749c2sm9HpAEaGz1_8ohV19j8w";
        byte[] byteToken = token.getBytes();
        CommandAPDU commandAPDU = new CommandAPDU(0x00, 0x03, 0x00, 0x00, byteToken);
        ResponseAPDU responseAPDU = simulator.transmitCommand(commandAPDU);

        byte[] salt = responseAPDU.getData();

        for (short i = 0; i < salt.length; i++) {
            System.out.print(String.format("%02x", salt[i]));
        }
        System.out.println();
    }

}
