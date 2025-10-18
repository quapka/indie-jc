package tests;

// import applet.Base64UrlSafeDecoder.*;
import applet.Base64UrlSafeDecoder;

import java.util.Base64;
import java.util.Random;
import java.util.Arrays;

import org.junit.Assert;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.*;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

public class Base64UrlSafeDecoderTest {
    @Test
    public void testDecoding() throws Exception {
        Random rand = new Random();
        int size = rand.nextInt(16);
        // int size = 5;
        // String input = "{\"typ\":\"JWT\", \"alg\":\"HS256\"}";

        byte[] bytes = new byte[size];
        // System.out.println(String.format("input: \"%s\"", new String(bytes, "ASCII")));
        System.out.println(String.format("Length: \"%s\"", bytes.length));
        bytes = new byte[size];
        // bytes[size - 1] = (byte) 0xff;
        // byte[] bytes = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!'};
        // short size = (short) bytes.length;
        rand.nextBytes(bytes);

        short NO_OFFSET = 0;

        Base64UrlSafeDecoder jcDecoder = new Base64UrlSafeDecoder();

        String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        // String encoded = Base64.getUrlEncoder().encodeToString(bytes);
        // System.out.println(String.format("\"%s\"", new String(bytes, "ASCII")));
        System.out.println(encoded);

        short inputLen = (short) encoded.getBytes().length;
        byte[] in = new byte[inputLen];
        byte[] out = new byte[size];

        System.out.println(inputLen);

        byte[] expected = Base64.getUrlDecoder().decode(encoded);
        // System.out.println(String.format("Expected: \"%s\"", new String(expected, "ASCII")));
        in = Arrays.copyOfRange(encoded.getBytes(), 0, inputLen);


        short decodedSize = jcDecoder.decodeBase64Urlsafe(in, NO_OFFSET, inputLen, out, NO_OFFSET);
        System.out.println(String.format("exp len: %d got: %d", bytes.length, decodedSize));
        // Assert.assertEquals(decodedSize, size);

        System.out.println(String.format("in buffer: \"%s\"", new String(in, "ASCII")));

        // System.out.println(String.format("\"%s\"", new String(out, "ASCII")));
        // System.out.println(out);

        for (short i = 0; i < size; i++ ) {
            System.out.print(String.format("%02X", bytes[i]));
        }
        System.out.println();
        for (short i = 0; i < decodedSize; i++ ) {
            System.out.print(String.format("%02X", out[i]));
        }
        System.out.println();


        Assert.assertArrayEquals(bytes, out);
        Assert.assertEquals(size, decodedSize);
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15})
    public void testVaryingSizeDecoding(int size) throws Exception {
        Base64UrlSafeDecoder jcDecoder = new Base64UrlSafeDecoder();

        byte[] bytes = new byte[size];
        Random rand = new Random();
        rand.nextBytes(bytes);

        String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        byte[] expected = Base64.getUrlDecoder().decode(encoded);

        byte[] in = Arrays.copyOfRange(encoded.getBytes(), 0, encoded.getBytes().length);
        byte[] out = new byte[size];


        short gotSize = jcDecoder.decodeBase64Urlsafe(in, (short) 0, (short) in.length, out, (short) 0);
        // for (short i = 0; i < size; i++ ) {
        //     System.out.print(String.format("%02X", bytes[i]));
        // }
        // System.out.println();
        // for (short i = 0; i < size; i++ ) {
        //     System.out.print(String.format("%02X", out[i]));
        // }
        // System.out.println();

        Assert.assertArrayEquals(bytes, out);
        Assert.assertEquals(size, gotSize);
    }

    @Test
    public void testBrokenDecoding() throws Exception {
        // The following is some previous signature that was not decoded correctly
        // String encoded = "xCq2y0FELMvoQHbkemGp6K6S8hOfLo70smdZ6ucn1D6ThGitY0LcfAOD6LAk4y-IG2CkSKI_QnH_4ZLNQ0KQPg";
        // String encoded = "Se_hzy7p3ruGf2eflgvdqkQL1szTySUR277lXEVHPTYpz-5DLUs-iIxlFoa8CrBmx7LQTCEYflS6GZDa6UkDTA";
        String encoded = "-Y91z03FpuqjTQ6bhjecnaHD70VfyuHqnvSHPeyz8QF4rC6A0bKwolCW0xCHDvQC_fLxbZzLeyRS4PmiK6DSNQ";

        byte[] in = encoded.getBytes();
        byte[] expected = Base64.getUrlDecoder().decode(encoded);
        System.out.println("Expected:");
        for (short i = 0; i < expected.length; i++ ) {
            System.out.print(String.format("%02X", expected[i]));
        }
        byte[] out = new byte[expected.length];

        Base64UrlSafeDecoder jcDecoder = new Base64UrlSafeDecoder();
        short nDecoded = jcDecoder.decodeBase64Urlsafe(in, (short) 0, (short) in.length, out, (short) 0);

        System.out.println("\nGot:");
        for (short i = 0; i < nDecoded; i++ ) {
            System.out.print(String.format("%02X", out[i]));
        }
        // Assert.assertArrayEquals(expected, out);
        // System.out.print(String.format("%02X", expected[nDecoded - 1]));
        // System.out.print(String.format("%02X", out[nDecoded - 1]));
        // System.out.println(String.format("%02X", out[nDecoded - 1]));
        Assert.assertEquals(expected[nDecoded - 1], out[nDecoded - 1]);
        Assert.assertEquals(nDecoded, (short) expected.length);
        Assert.assertArrayEquals(expected, out);
    }

    @ParameterizedTest
    @ValueSource(ints = {0, 1, 2, 3, 4})
    public void testSharedInputOutputBuffer(int size) throws Exception {

        byte[] bytes = new byte[size];
        Random rand = new Random();
        rand.nextBytes(bytes);

        String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        byte[] expected = Base64.getUrlDecoder().decode(encoded);

        byte[] inOut = Arrays.copyOfRange(encoded.getBytes(), 0, encoded.getBytes().length);

        short gotSize = new Base64UrlSafeDecoder().decodeBase64Urlsafe(inOut, (short) 0, (short) inOut.length, inOut, (short) 0);

        Assert.assertEquals(expected.length, gotSize);
        // The decoded content in `inOut` is shorter, thus we compare only up to the expected size
        for (short i = 0; i < expected.length; i++ ) {
            Assert.assertEquals(expected[i], inOut[i]);
        }
    }

    @Disabled("Not implemented yet")
    @Test
    public void testOutputBufferTooSmall() throws Exception {}

    @Disabled("Not implemented yet")
    @Test
    public void testNonBase64Character() throws Exception {}

    @Disabled("Not implemented yet")
    @Test
    // @ParameterizedTest
    // @ValueSource(ints = {0, 1, 2, 3})
    public void testSinglePaddingByte(int paddingSize) throws Exception {}
}
