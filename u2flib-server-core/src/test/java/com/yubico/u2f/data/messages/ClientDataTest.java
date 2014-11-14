package com.yubico.u2f.data.messages;

import com.yubico.u2f.exceptions.U2fException;
import org.junit.Test;

import static com.yubico.u2f.data.messages.ClientData.canonicalizeOrigin;
import static org.junit.Assert.assertEquals;

public class ClientDataTest {

    @Test
    public void shouldCanonicalizeOrigin() throws U2fException {
        assertEquals("http://example.com", canonicalizeOrigin("http://example.com"));
        assertEquals("http://example.com", canonicalizeOrigin("http://example.com/"));
        assertEquals("http://example.com", canonicalizeOrigin("http://example.com/foo"));
        assertEquals("http://example.com", canonicalizeOrigin("http://example.com/foo?bar=b"));
        assertEquals("http://example.com", canonicalizeOrigin("http://example.com/foo#fragment"));
        assertEquals("https://example.com", canonicalizeOrigin("https://example.com"));
        assertEquals("https://example.com", canonicalizeOrigin("https://example.com/foo"));
        assertEquals("android:apk-key-hash:2jmj7l5rSw0yVb/vlWAYkK/YBwk",
                canonicalizeOrigin("android:apk-key-hash:2jmj7l5rSw0yVb/vlWAYkK/YBwk"));
    }
}