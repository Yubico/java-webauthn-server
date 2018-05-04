package com.yubico.u2f.data.messages.key.util;

import com.yubico.u2f.exceptions.U2fBadInputException;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class U2fB64EncodingTest {
    @Test
    public void encodeTest() {
        byte[] input = "Test".getBytes();
        String base64Data = U2fB64Encoding.encode(input);

        // No padding.
        assertEquals("VGVzdA", base64Data);
    }

    @Test
    public void decodeTest() throws U2fBadInputException {
        String base64Data = "VGVzdA";
        String base64DataWithPadding = "VGVzdA==";
        String base64DataEmpty = "";

        // Verify that Base64 data with and without padding ('=') are decoded correctly.
        String out1 = new String(U2fB64Encoding.decode(base64Data));
        String out2 = new String(U2fB64Encoding.decode(base64DataWithPadding));
        String out3 = new String(U2fB64Encoding.decode(base64DataEmpty));

        assertEquals(out1, out2);
        assertEquals(out1, "Test");
        assertEquals(out3, "");
    }

    @Test(expected = U2fBadInputException.class)
    public void decodeBadAlphabetTest() throws U2fBadInputException {
        U2fB64Encoding.decode("****");
    }

    @Test(expected = U2fBadInputException.class)
    public void decodeBadPaddingTest() throws U2fBadInputException {
        U2fB64Encoding.decode("A===");
    }
}
