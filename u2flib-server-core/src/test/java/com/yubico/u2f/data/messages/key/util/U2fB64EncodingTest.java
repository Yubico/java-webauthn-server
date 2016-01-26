package com.yubico.u2f.data.messages.key.util;

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
    public void decodeTest() {
        String base64Data = "VGVzdA";
        String base64DataWithPadding = "VGVzdA==";

        // Verify that Base64 data with and without padding ('=') are decoded correctly.
        String out1 = new String(U2fB64Encoding.decode(base64Data));
        String out2 = new String(U2fB64Encoding.decode(base64DataWithPadding));

        assertEquals(out1, out2);
        assertEquals(out1, "Test");
    }
}