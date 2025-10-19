package tests;

// import applet.Base64UrlSafeDecoder.*;
import applet.Base64UrlSafeDecoder;

import java.util.Base64;
import java.util.Random;
import java.util.Arrays;

import org.junit.Assert;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.junit.Rule;
import org.junit.jupiter.api.*;
import java.util.stream.*;

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

    @Test
    // @BenchmarkOptions(concurrency = 1, warmupRounds = 0, benchmarkRounds = 10)
    public void testBenchmarkDecoding() throws Exception {

        String encoded = "Dk8SWM_Z3oZB-uwzAmTL9e4c1AGqpBAKNe2x56k9dWnCUL3gpRRpO-kUsgWtCDaUTjrNWsrbHtdpSlgoxKoYy6fXokmmylaS_Bw1x8nC--wZQAtoZCsA96yRFRz3ywFjS1lRzRc6s7YE10cRVMAD_qE68Y9WTo50G_GQlGruZg3h4pO2DYrDMNGhArE89o2kGCReFZIhUplYEREveCEoC77p59D2kIPX9vo7kuiKIfkYPd-dnVJ24ghil4YuySlk3austhHrhKFJE7zasBDuIRz1pA0SXvEGVHZoLNAAf4JcIK7E8WAq4WdznmtgkCnJBGP8GB3egCBpcZNBVc2NQv137Qz-nXk9LbCTerpjNcyVTU9hASlQ4viCSozmH5dPpi3JPPM2_eVAL_W48N-Tx_fD7PGTP2SJtnMerGOoTGfhpuYMYQBxFYb73Iou0PjaNUYcd7wLJ9zdQW-g3ndeCl1kf3srtTL0q6mzJA7A_l_AfT2Y-u6rH6rNoywdcyoza8LzwwjtsFCdTOYBIRZLVe2F9nPfoIdi3ZX6xRyV9-aBScXABWNScRF6tgtt_irvcsSyW5FdVd48hAWfiQFn2buOWicAjI94_F5W8-ok8xXtUfSRSWRDeg_KIhVH5wTlVaQu1y59OHEa5MK2BECsmV3yOf3UxUCqpcyEPOsyI88yGk5IlSIhHmriDQQca9aJp517dxWDpv_OIZuHQhFoqFiOQ_-Txa0Vr2cKMwdRTW8SmH-ggft1wWCc7o7JQboecs3VzlXj-YbxCo3ZjSaXHcsait-hq4bLs2jCzjM5dUBNgzmaYVOTQ_pQspLrdChwYowpj5M7PcUkOQzI5xMPhFt7mDwNvgNO2iDdbVK0Zo9LSSEkit2leZWClVKAWJpiM3EQNQVjojpkSF-eZrZzSF_8tH5K_Au868hXFkuKzXYPcYu4yS9oJa4Q_nC_4AuaWIfWe6w5ac2P-2USzIt63UzIE9UsJsDcleLEQGs3AdhYe_hJIL1FqO7h9M850Z-H7YWFZNYSjiY3-9cgajcdrmMhh_sm0uPx-ZdUYP1ifUkZi7-mw5PlsXYwOTUxgXPa4BJKT9TW0JCmGu2MN7BXtZkrtn3DbitdfMWwQChTb64cYjCtU3o1Em3kj7A4MdI7W14JcPg3m_UyT0zCLNQlRcdSSeRiS38Yy5mwiQnaC5_xfQDJWkhreseoJRkNLrfkdKLrTNKWPQfCxVb141zngBOZDWc2BAk7L_hjiRF4yC8dYU2QCJZLAVem2uq0PCm4GFM6DKtxJ92hwqipb3Fgo55ZDn1-7aEXEwm_QKGvVSOBVCBOLB-adBgRW7TVC7FcNQp3_kF7aTiDNzq7flF44w";

        Base64UrlSafeDecoder jcDecoder = new Base64UrlSafeDecoder();

        byte[] expected = Base64.getUrlDecoder().decode(encoded);

        short inputLen = (short) encoded.getBytes().length;
        byte[] in = new byte[inputLen];
        byte[] out = new byte[expected.length];

        in = Arrays.copyOfRange(encoded.getBytes(), 0, inputLen);

        long starTime = 0;
        long endTime = 0;
        int numTests = 100;
        long[] results = new long[numTests];
        starTime = System.nanoTime();
        for (int i = 0; i < numTests; i++) {
            jcDecoder.decodeBase64Urlsafe(in, (short) 0, inputLen, out, (short) 0);
        }
        long sum = LongStream.of(results).sum();
        System.out.println("Average decoding time: " + ((System.nanoTime() - starTime) / results.length) + " ns");
        // 76474
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
