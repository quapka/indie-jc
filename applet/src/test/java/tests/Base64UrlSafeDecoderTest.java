package tests;

// import applet.Base64UrlSafeDecoder.*;
import applet.Base64UrlSafeDecoder;

import java.util.Base64;
import java.util.Random;
import java.util.Arrays;

import org.junit.Assert;
import org.junit.jupiter.api.*;

public class Base64UrlSafeDecoderTest {
    @Test
    public void testDecoding() throws Exception {
        short size = 1024;
        // String input = "{\"typ\":\"JWT\", \"alg\":\"HS256\"}";

        byte[] bytes = new byte[size];
        // System.out.println(String.format("input: \"%s\"", new String(bytes, "ASCII")));
        System.out.println(String.format("Length: \"%s\"", bytes.length));
        bytes = new byte[size];
        // byte[] bytes = {'H', 'e', 'l', 'l', 'o', ' ', 'W', 'o', 'r', 'l', 'd', '!'};
        // short size = (short) bytes.length;
        Random rand = new Random();
        rand.nextBytes(bytes);

        short NO_OFFSET = 0;
        byte[] in = new byte[size*2];
        byte[] out = new byte[size*2];

        Base64UrlSafeDecoder jcDecoder = new Base64UrlSafeDecoder();

        String encoded = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
        // String encoded = Base64.getUrlEncoder().encodeToString(bytes);
        // System.out.println(String.format("\"%s\"", new String(bytes, "ASCII")));
        System.out.println(encoded);

        short inputLen = (short) encoded.getBytes().length;
        System.out.println(inputLen);

        byte[] expected = Base64.getUrlDecoder().decode(encoded);
        // System.out.println(String.format("Expected: \"%s\"", new String(expected, "ASCII")));
        in = Arrays.copyOfRange(encoded.getBytes(), 0, inputLen);


        short gotSize = jcDecoder.decodeBase64Urlsafe(in, NO_OFFSET, inputLen, out, NO_OFFSET);
        System.out.println(String.format("exp len: %d got: %d", bytes.length, gotSize));
        // Assert.assertEquals(gotSize, size);

        System.out.println(String.format("in buffer: \"%s\"", new String(in, "ASCII")));

        // System.out.println(String.format("\"%s\"", new String(out, "ASCII")));
        // System.out.println(out);

        byte[] slice = Arrays.copyOfRange(out, 0, gotSize);

        Assert.assertArrayEquals(expected, slice);
    }
}
