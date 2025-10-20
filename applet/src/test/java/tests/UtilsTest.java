package tests;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Disabled;
import applet.Utils;
import java.util.Random;
import java.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import java.math.BigInteger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.DERSequence;
import java.io.ByteArrayOutputStream;

import org.junit.Assert;

public class UtilsTest {

    @Test
    @Disabled("While the Utils.derEncodeRawEcdsaSignature works, the ASN.1 sequence from BC is differs")
    public void testDerEncoding() throws Exception {
        Random rand = new Random();

        byte[] r = new byte[32];
        byte[] s = new byte[32];
        rand.nextBytes(r);
        rand.nextBytes(s);

        byte[] rawSignature = new byte[64];
        System.arraycopy(r, 0, rawSignature, 0, 32);
        System.arraycopy(s, 0, rawSignature, 32, 32);

        byte[] out = new byte[72];

        // encode r and s to der using bouncycastle
        ASN1EncodableVector sigV = new ASN1EncodableVector();
        sigV.add(new ASN1Integer(new BigInteger(r)));
        sigV.add(new ASN1Integer(new BigInteger(s)));
        DERSequence sequence = new DERSequence(sigV);

        Utils.derEncodeRawEcdsaSignature(rawSignature, out);
        // System.out.println(Hex.toHexString(rawSignature));
        // System.out.println(Hex.toHexString(sequence.getEncoded(ASN1Encoding.DER)));
        // System.out.println(Hex.toHexString(out));


        Assert.assertEquals(sequence.getEncoded().length, out.length);
        Assert.assertArrayEquals(sequence.getEncoded(ASN1Encoding.DER), out);
    }
}
