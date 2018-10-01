package com.yubico.webauthn.data;

import com.yubico.webauthn.data.exception.Base64UrlException;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class ByteArrayTest {

    @Test
    public void testEncodeBase64Url() {
        byte[] input = "Test".getBytes();
        String base64Data = new ByteArray(input).getBase64Url();

        // No padding.
        assertEquals("VGVzdA", base64Data);
    }

    @Test
    public void decodeTest() throws Base64UrlException {
        String base64Data = "VGVzdA";
        String base64DataWithPadding = "VGVzdA==";
        String base64DataEmpty = "";

        // Verify that Base64 data with and without padding ('=') are decoded correctly.
        String out1 = new String(ByteArray.fromBase64Url(base64Data).getBytes());
        String out2 = new String(ByteArray.fromBase64Url(base64DataWithPadding).getBytes());
        String out3 = new String(ByteArray.fromBase64Url(base64DataEmpty).getBytes());

        assertEquals(out1, out2);
        assertEquals(out1, "Test");
        assertEquals(out3, "");
    }

    @Test(expected = Base64UrlException.class)
    public void decodeBadAlphabetTest() throws Base64UrlException {
        ByteArray.fromBase64Url("****");
    }

    @Test(expected = Base64UrlException.class)
    public void decodeBadPaddingTest() throws Base64UrlException {
        ByteArray.fromBase64Url("A===");
    }
}
