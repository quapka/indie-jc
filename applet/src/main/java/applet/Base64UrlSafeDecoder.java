package applet;

import javacardx.framework.math.*;

public class Base64UrlSafeDecoder
{
    private BigNumber baseBN, indexBN;
    byte[] tmp = new byte[4];

    private static final byte[] Base64UrlSafeAlphabet = {
        'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
        'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
        'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
        'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '-', '_'
    };

    // private byte[] temp = new byte[3];

    public Base64UrlSafeDecoder() {
        // simulate an int value
        baseBN = new BigNumber((short) 4);
        indexBN = new BigNumber((short) 4);
        // tmp = new byte[4];
        baseBN.reset();
        indexBN.reset();
        // indexBN.init(tmp, (short) 0, (short) 4, BigNumber.FORMAT_HEX);
        // indexBN.init(tmp, (short) 0, (short) 4, BigNumber.FORMAT_HEX);
    }

    public short decodeBase64Urlsafe(byte[] input, short inputOffset, short inputLength, byte[] output, short outputOffset) {
        // This implemntation expects the input to have the correct alphabet
        short n_written = 0;
        // Not all implmentation will have int?, yeah bitten me now
        // int base = 0;
        // base = high << 16 || low;
        short high = 0;
        short low = 0;

        byte pad = 0;
        short index = 0;
        byte shift = 0;
        short bLen = 0;

        for (short i = 0; i < inputLength; i += 4) {
            // base = 0;
            high = 0;
            low = 0;
            baseBN.reset();
            indexBN.reset();
            tmp[0] = 0x00;
            tmp[1] = 0x00;
            tmp[2] = 0x00;
            tmp[3] = 0x00;
            for (byte j = 0; j < 4; j++) {
                // NOTE if the search is slow, try using Util.arrayFindGeneric?
                try {
                    index = (short) base64CharToValue(input[(short) (inputOffset + j + i)]);
                } catch (ArrayIndexOutOfBoundsException e) {
                    pad += (byte) 1;
                    index = 0;
                }
                if (index == 255) {
                    return (byte) 255;
                }
                // tmp[3] = index;
                // System.out.println("index raw:");
                // for(short l = 0; l < 4; l++) {
                //     System.out.print(String.format("%02x", tmp[l]));
                // }
                // System.out.println();
                // System.out.println(String.format("index: %d", index));
                indexBN.add(tmp, (short) 0, (short) 4, BigNumber.FORMAT_HEX);

                indexBN.toBytes(tmp, (short) 0, (short) 4, BigNumber.FORMAT_HEX);
                // System.out.print(String.format("index: %d indexBN: ", index));
                for(short l = 0; l < 4; l++) {
                    // System.out.print(String.format("%02x", tmp[l]));
                }
                // System.out.println();

                tmp[0] = 0x00;
                tmp[1] = 0x00;
                tmp[2] = 0x00;
                tmp[3] = 0x00;
                // tmp = {0x00, 0x00, 0x00, 0x00};
                // j:0 18
                // j:1 12
                // j:2 6
                // j:3 0
                shift = (byte) ((3 - j) * 6);
                // System.out.println(String.format("shift: %d", shift));
                // implement indexBN * (2**shift) instead of binary shift
                tmp[3] = 0x02;
                for (short k = 0; k < shift; k++) {
                    indexBN.multiply(tmp, (short) 0, (short) 4, BigNumber.FORMAT_HEX);
                }
                // tmp[0] = 0x00;
                // tmp[1] = 0x00;
                // tmp[2] = 0x00;
                // tmp[3] = 0x00;
                // bLen = indexBN.getByteLength(BigNumber.FORMAT_HEX);
                indexBN.toBytes(tmp, (short) 0, (short) 4, BigNumber.FORMAT_HEX);
                // System.out.println("before add indexBN:");
                for(short l = 0; l < 4; l++) {
                    // System.out.print(String.format("%02x", tmp[l]));
                }
                // System.out.println();

                baseBN.add(tmp, (short) 0, (short) 4, BigNumber.FORMAT_HEX);

                if (j == 3) {
                    low |= index & 0x3F;
                } else if (j == 2) {
                    low |= index << 6;
                } else if (j == 1) {
                    low |= index << 12;
                    // high |= (index << 12) >> 16;
                    high |= index >> 4;
                } else if (j == 0) {
                    // high |= (index << 18) >> 16;
                    high |= index << 2;
                }
                // base += index << ((3 - j) * 6);
                // low += index << ((3 - j) * 6);


            }
            // FIXME how to detect that the padding was = or == and we don't want
            // to write the last 1 or 2 bytes?
            // output[outputOffset + n_written + 0] = (byte) (base >> 16 & 0xFF);
            // output[outputOffset + n_written + 1] = (byte) (base >>  8 & 0xFF);
            // output[outputOffset + n_written + 2] = (byte) (base >>  0 & 0xFF);

            // bLen = indexBN.getByteLength(BigNumber.FORMAT_HEX);
            baseBN.toBytes(tmp, (short) 0, (short) 4, BigNumber.FORMAT_HEX);
            // System.out.println("baseBN:");
            for(short l = 0; l < 4; l++) {
                // System.out.print(String.format("%02x", tmp[l]));
            }
            // System.out.println();
            // System.out.println();
            // System.out.println(String.format("base: %d", base));
            // System.out.println("baseBN:");
            // for(short l = 0; l < 4; l++) {
            //     System.out.print(String.format("%02x", tmp[l]));
            // }
            // System.out.println();

            // output[outputOffset + n_written + 0] = (byte) (tmp[1] & 0xFF);
            // output[outputOffset + n_written + 1] = (byte) (tmp[2] & 0xFF);
            // output[outputOffset + n_written + 2] = (byte) (tmp[3] & 0xFF);
            // System.out.println(String.format("base >> 16: %02x high %02x", (byte) (base >> 16 & 0xFF), (byte) high >> 0 & 0xFF));
            // System.out.println(String.format("base >> 16: %02x low %02x", (byte) (base >> 8 & 0xFF), (byte) low >> 8 & 0xFF));
            // System.out.println(String.format("base >> 16: %02x low %02x", (byte) (base >> 0 & 0xFF), (byte) low >> 0 & 0xFF));

            output[(short) (outputOffset + n_written + 0)] = (byte) (high >> 0 & 0xFF);
            output[(short) (outputOffset + n_written + 1)] = (byte) (low  >> 8 & 0xFF);
            output[(short) (outputOffset + n_written + 2)] = (byte) (low  >> 0 & 0xFF);

            n_written += 3;
        }

        return (short) (n_written - pad);
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
