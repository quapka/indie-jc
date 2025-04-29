package applet;

public class Base64UrlSafeDecoder
{
    private static final byte[] Base64UrlSafeAlphabet = {
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
        'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
        'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
        'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_'
    };

    private byte[] temp = new byte[3];

    Base64UrlSafeDecoder() {
    }

    public void works() {
        System.out.println("it works");
    }

    public short decodeBase64Urlsafe(byte[] input, short inputOffset, short inputLength, byte[] output, short outputOffset) {
        short n_written = 0;
        // byte[] temp = new byte[3];
        int base = 0;
        System.out.println("about to decode");

        for (short i = 0; i < inputLength; i += 4) {
            base = 0;
            for (byte j = 0; j <  4; j++) {
                // NOTE if the search is slow, try using Util.arrayFindGeneric?
                byte index = base64CharToValue(input[inputOffset + j + i]);
                if (index == 255) {
                    return (byte) 255;
                }
                base += index << ((3 - j) * 6);
            }
            output[outputOffset + n_written + 0] = (byte) (base >> 16 & 0xFF);
            output[outputOffset + n_written + 1] = (byte) (base >>  8 & 0xFF);
            output[outputOffset + n_written + 2] = (byte) (base >>  0 & 0xFF);
            n_written += 3;
        }

        return n_written;
    }

    // FIXME is there a quicker way to do this byte resolution? Long switch-case?
    private byte base64CharToValue(byte c) {
        for (byte i = 0; i < Base64UrlSafeAlphabet.length; i++) {
            if (Base64UrlSafeAlphabet[i] == c) {
                return i;
            }
        }
        // FIXME returning 0 here might not be fully correct, but seems to work fine.
        // if ( c == '=' ) {
        //     return 0;
        // }
        return 0;
    }
}
