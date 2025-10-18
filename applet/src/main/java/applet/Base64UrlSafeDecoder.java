package applet;

import javacard.framework.ISOException;
import javacard.framework.ISO7816;

public class Base64UrlSafeDecoder
{
    private static final byte[] Base64UrlSafeAlphabet = {
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
        'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
        'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
        'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_'
    };

    public Base64UrlSafeDecoder() {}

    // FIXME add some kind of check for when output would get overwriten if the input is too long
    public short decodeBase64Urlsafe(byte[] input, short inputOffset, short inputLength, byte[] output, short outputOffset) {
        short n_written = 0;
        byte high = 0;
        short low = 0;
        byte index = 0;
        byte remainder = (byte) (inputLength % 4);

        for (short i = 0; i < (short) ((inputLength / 4) * 4); i += 4) {
            high = 0;
            low = 0;
            for (byte j = 0; j < 4; j++) {
                index = base64CharToValue(input[(short) (inputOffset + i + j)]);

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
            output[(short) (outputOffset + n_written + 0)] = (byte) ((high    ) & 0xFF);
            output[(short) (outputOffset + n_written + 1)] = (byte) ((low >> 8) & 0xFF);
            output[(short) (outputOffset + n_written + 2)] = (byte) ((low     ) & 0xFF);
            n_written += 3;
        }

        if ( remainder == 3 ) {
            // ------ --|---- ----|00 000000
            // ------|-- ----|---- 00|000000
            low  = (short) (base64CharToValue(input[(short) (inputOffset + inputLength - 3)]) << 10);
            low |= (short) (base64CharToValue(input[(short) (inputOffset + inputLength - 2)]) <<  4);
            low |= (short) (base64CharToValue(input[(short) (inputOffset + inputLength - 1)]) >>  2);

            output[(short) (outputOffset + n_written + 0)] = (byte) ((low >> 8) & 0xFF);
            output[(short) (outputOffset + n_written + 1)] = (byte) ((low >> 0) & 0xFF);

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

    // FIXME is there a quicker way to do this byte resolution? Long switch-case?
    private byte base64CharToValue(byte c) {
        for (byte i = 0; i < Base64UrlSafeAlphabet.length; i++) {
            if (Base64UrlSafeAlphabet[i] == c) {
                return i;
            }
        }

        if (c == '=') {
            return 0;
        }

        ISOException.throwIt(Consts.ERR.INVALID_INPUT);
        return 0;
    }
}
