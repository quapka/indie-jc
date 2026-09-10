package applet;

import javacard.framework.ISOException;
import javacard.framework.ISO7816;

public class Base64UrlSafeDecoder
{
    // Lookup table for base64url decoding (128 bytes)
    // Maps ASCII values to 6-bit base64 values
    // Invalid characters map to -1 (0xFF)
    private static final byte[] DECODE_TABLE = {
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0-15
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 16-31
        -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, // 32-47 (45='-')
        52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1,  0, -1, -1, // 48-63 (48-57='0'-'9', 61='=')
        -1,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, // 64-79 (65-90='A'-'Z')
        15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, 63, // 80-95 (95='_')
        -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, // 96-111 (97-122='a'-'z')
        41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1  // 112-127
    };

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
                // Convert Base64 character to its 6-bit value using lookup table
                if (value < 0 || value >= 128) {
                    ISOException.throwIt(Consts.ERR.INVALID_INPUT);
                    return 0;
                }
                index = DECODE_TABLE[value];
                if (index < 0) {
                    ISOException.throwIt(Consts.ERR.INVALID_INPUT);
                    return 0;
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
        if (value < 0 || value >= 128) {
            ISOException.throwIt(Consts.ERR.INVALID_INPUT);
            return 0;
        }
        byte decoded = DECODE_TABLE[value];
        if (decoded < 0) {
            ISOException.throwIt(Consts.ERR.INVALID_INPUT);
            return 0;
        }
        return decoded;
    }
}
