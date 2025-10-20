package applet;

import javacard.framework.ISOException;
import javacard.framework.ISO7816;

public class Base64UrlSafeDecoder
{
    public Base64UrlSafeDecoder() {}

    // FIXME add some kind of check for when output would get overwriten if the input is too long
    public short decodeBase64Urlsafe(byte[] input, short inputOffset, short inputLength, byte[] output, short outputOffset) {
        short n_written = 0;
        byte high = 0;
        short low = 0;
        byte index = 0;
        byte remainder = (byte) (inputLength % 4);
        byte value = 0;

        for (short i = 0; i < (short) ((inputLength / 4) * 4); i += 4) {
            high = 0;
            low = 0;
            for (byte j = 0; j < 4; j++) {
                value = input[(short) (inputOffset + i + j)];
                // Convert Base64 character to its 6-bit value inplace
                if ( value >= 65 && value <= 90) {
                    index = (byte) (value - 65);
                } else if ( value >= 97 && value <= 122) {
                    index = (byte) (value - 71);
                } else if ( value >= 48 && value <= 57 ) {
                    index = (byte) (value + 4);
                } else if ( value == '-' ) {
                    index = 62;
                } else if ( value == '_' ) {
                    index = 63;
                } else if ( value == '=' ) {
                    index = 0;
                }

                if (j == 3) {
                    low |= index;
                } else if (j == 2) {
                    low |= index << 6;
                } else if (j == 1) {
                    low |= index << 12;
                    high |= index >> 4;
                } else if (j == 0) {
                    high |= index << 2;
                }
            }
            output[(short) (outputOffset + n_written + 0)] = high;
            output[(short) (outputOffset + n_written + 1)] = (byte) ((low >> 8));
            output[(short) (outputOffset + n_written + 2)] = (byte) ((low     ));
            n_written += 3;
        }

        if ( remainder == 3 ) {
            // ------ --|---- ----|00 000000
            // ------|-- ----|---- 00|000000
            low  = (short) (base64CharToValue(input[(short) (inputOffset + inputLength - 3)]) << 10);
            low |= (short) (base64CharToValue(input[(short) (inputOffset + inputLength - 2)]) <<  4);
            low |= (short) (base64CharToValue(input[(short) (inputOffset + inputLength - 1)]) >>  2);

            output[(short) (outputOffset + n_written + 0)] = (byte) ((low >> 8));
            output[(short) (outputOffset + n_written + 1)] = (byte) ((low >> 0));

            n_written += 2;
        } else if ( remainder == 2 ) {
            // ------ --|0000 0000|00 000000
            // ------|-- 0000|0000 00|000000
            low  = (short) (base64CharToValue(input[(short) (inputOffset + inputLength - 2)]) << 2);
            low |= (short) (base64CharToValue(input[(short) (inputOffset + inputLength - 1)]) >> 4);

            output[(short) (outputOffset + n_written + 0)] = (byte) (low);

            n_written += 1;
        } else if ( remainder == 1 ) {
            ISOException.throwIt(Consts.ERR.INVALID_INPUT);
        }

        return n_written;
    }

    private byte base64CharToValue(byte value) {
        switch (value) {
            case 'A': return 0;
            case 'B': return 1;
            case 'C': return 2;
            case 'D': return 3;
            case 'E': return 4;
            case 'F': return 5;
            case 'G': return 6;
            case 'H': return 7;
            case 'I': return 8;
            case 'J': return 9;
            case 'K': return 10;
            case 'L': return 11;
            case 'M': return 12;
            case 'N': return 13;
            case 'O': return 14;
            case 'P': return 15;
            case 'Q': return 16;
            case 'R': return 17;
            case 'S': return 18;
            case 'T': return 19;
            case 'U': return 20;
            case 'V': return 21;
            case 'W': return 22;
            case 'X': return 23;
            case 'Y': return 24;
            case 'Z': return 25;
            case 'a': return 26;
            case 'b': return 27;
            case 'c': return 28;
            case 'd': return 29;
            case 'e': return 30;
            case 'f': return 31;
            case 'g': return 32;
            case 'h': return 33;
            case 'i': return 34;
            case 'j': return 35;
            case 'k': return 36;
            case 'l': return 37;
            case 'm': return 38;
            case 'n': return 39;
            case 'o': return 40;
            case 'p': return 41;
            case 'q': return 42;
            case 'r': return 43;
            case 's': return 44;
            case 't': return 45;
            case 'u': return 46;
            case 'v': return 47;
            case 'w': return 48;
            case 'x': return 49;
            case 'y': return 50;
            case 'z': return 51;
            case '0': return 52;
            case '1': return 53;
            case '2': return 54;
            case '3': return 55;
            case '4': return 56;
            case '5': return 57;
            case '6': return 58;
            case '7': return 59;
            case '8': return 60;
            case '9': return 61;
            case '-': return 62;
            case '_': return 63;
            case '=': return 0;
            default:
                ISOException.throwIt(Consts.ERR.INVALID_INPUT);
                return 0;
        }
    }
}
