package applet;

import javacard.framework.*;

public class HelloWorldApplet extends Applet
{

	private static final byte[] helloWorld = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!'};
	private static final byte[] Good = {'G', 'O', 'O', 'D'};
	private static final byte[] Bad = {'B', 'A', 'D'};

	public static void install(byte[] bArray, short bOffset, byte bLength)
	{
		new HelloWorldApplet();
	}

	public HelloWorldApplet()
	{
		register();
	}

	public void process(APDU apdu)
	{
        byte[] buffer = apdu.getBuffer();
        byte cla = buffer[ISO7816.OFFSET_CLA];
        byte ins = buffer[ISO7816.OFFSET_INS];

        if ( cla == 0x02 ) {
            sendGood(apdu);
        } else if ( cla == 0x04 ) {
            sendBad(apdu);
        }

		// sendHelloWorld(apdu);
	}

	// part of https://github.com/devrandom/javacard-helloworld/blob/master/src/main/java/org/gitian/javacard/HelloWorldApplet.java#L38
	private void sendHelloWorld(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		short length = (short) helloWorld.length;
		Util.arrayCopyNonAtomic(helloWorld, (short) 0, buffer, (short) 0, length);
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
}
