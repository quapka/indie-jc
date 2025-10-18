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

        byte[] bytes = new byte[size];
        bytes = new byte[size];
        rand.nextBytes(bytes);

        Base64UrlSafeDecoder jcDecoder = new Base64UrlSafeDecoder();

        String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);

        short inputLen = (short) encoded.getBytes().length;
        byte[] in = new byte[inputLen];
        byte[] out = new byte[size];

        byte[] expected = Base64.getUrlDecoder().decode(encoded);
        in = Arrays.copyOfRange(encoded.getBytes(), 0, inputLen);

        short decodedSize = jcDecoder.decodeBase64Urlsafe(in, (short) 0, inputLen, out, (short) 0);

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

        Assert.assertArrayEquals(bytes, out);
        Assert.assertEquals(size, gotSize);
    }

    @Test
    public void testBrokenDecoding() throws Exception {
        String encoded = "-Y91z03FpuqjTQ6bhjecnaHD70VfyuHqnvSHPeyz8QF4rC6A0bKwolCW0xCHDvQC_fLxbZzLeyRS4PmiK6DSNQ";

        byte[] in = encoded.getBytes();
        byte[] expected = Base64.getUrlDecoder().decode(encoded);
        byte[] out = new byte[expected.length];

        Base64UrlSafeDecoder jcDecoder = new Base64UrlSafeDecoder();
        short nDecoded = jcDecoder.decodeBase64Urlsafe(in, (short) 0, (short) in.length, out, (short) 0);

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

    // TODO
    @Disabled("Not implemented yet")
    @Test
    public void testNonZeroOffsetInput() throws Exception {}

    // TODO
    @Disabled("Not implemented yet")
    @Test
    public void testNonZeroOffsetOutput() throws Exception {}

    // TODO
    @Disabled("Not implemented yet")
    @Test
    public void testOutputBufferTooSmall() throws Exception {}

    // TODO
    @Disabled("Not implemented yet")
    @Test
    public void testNonBase64Character() throws Exception {}

    // TODO
    @Disabled("Not implemented yet")
    @Test
    // @ParameterizedTest
    // @ValueSource(ints = {0, 1, 2, 3})
    public void testSinglePaddingByte(int paddingSize) throws Exception {}
}
