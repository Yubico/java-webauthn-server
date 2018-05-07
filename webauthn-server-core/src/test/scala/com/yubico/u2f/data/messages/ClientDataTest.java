package com.yubico.u2f.data.messages;

import com.google.common.collect.ImmutableSet;
import com.yubico.u2f.exceptions.U2fBadInputException;
import org.junit.Test;

import static com.yubico.u2f.data.messages.ClientData.canonicalizeOrigin;
import static com.yubico.u2f.testdata.TestVectors.APP_ID_ENROLL;
import static com.yubico.u2f.testdata.TestVectors.CLIENT_DATA_REGISTRATION_BASE64;
import static com.yubico.u2f.testdata.TestVectors.SERVER_CHALLENGE_REGISTER_BASE64;
import static org.junit.Assert.assertEquals;

public class ClientDataTest {

    @Test
    public void shouldCanonicalizeOrigin() {
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

    @Test
    public void shouldCheckContent() throws U2fBadInputException {
        ClientData clientData = new ClientData(CLIENT_DATA_REGISTRATION_BASE64);
        clientData.checkContent("navigator.id.finishEnrollment", SERVER_CHALLENGE_REGISTER_BASE64, ImmutableSet.of(APP_ID_ENROLL));
    }
}
