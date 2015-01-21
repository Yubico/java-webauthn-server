package com.yubico.u2f.data.messages;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.yubico.u2f.TestUtils;
import org.junit.Test;

import static com.yubico.u2f.testdata.TestVectors.*;
import static org.junit.Assert.assertEquals;

public class AuthenticateResponseTest {
    public static final String JSON = "{\"clientData\":\"eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZ2V0QXNzZXJ0aW9uIiwiY2hhbGxlbmdlIjoib3BzWHFVaWZEcmlBQW1XY2xpbmZiUzBlLVVTWTBDZ3lKSGVfT3RkN3o4byIsImNpZF9wdWJrZXkiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJIelF3bGZYWDdRNFM1TXRDQ25aVU5CdzNSTXpQTzl0T3lXakJxUmw0dEo4IiwieSI6IlhWZ3VHRkxJWngxZlhnM3dOcWZkYm43NWhpNC1fNy1CeGhNbGp3NDJIdDQifSwib3JpZ2luIjoiaHR0cDovL2V4YW1wbGUuY29tIn0\",\"signatureData\":\"\",\"keyHandle\":\"KlUt_bdHftZf2EEz-GGWAQsiFbV9p10xW3uej-LjklpgGVUbq2HRZZFlnLrwC0lQ96v-ZmDi4Ab3aGi3ctcMJQ\"}";

    @Test
    public void testGetters() throws Exception {
        AuthenticateResponse authenticateResponse = new AuthenticateResponse(CLIENT_DATA_AUTHENTICATE_BASE64, "", KEY_HANDLE_BASE64);

        assertEquals(CLIENT_DATA_AUTHENTICATE, authenticateResponse.getClientData().toString());
        assertEquals(KEY_HANDLE_BASE64, authenticateResponse.getKeyHandle());
    }

    @Test
    public void testToAndFromJson() throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();
        AuthenticateResponse authenticateResponse = AuthenticateResponse.fromJson(JSON);
        AuthenticateResponse authenticateResponse2 = objectMapper.readValue(authenticateResponse.toJson(), AuthenticateResponse.class);

        assertEquals(authenticateResponse, authenticateResponse2);
        assertEquals(authenticateResponse.getRequestId(), authenticateResponse2.getRequestId());
        assertEquals(authenticateResponse.toJson(), objectMapper.writeValueAsString(authenticateResponse));
    }

    @Test
    public void testJavaSerializer() throws Exception {
        AuthenticateResponse authenticateResponse = AuthenticateResponse.fromJson(JSON);
        AuthenticateResponse authenticateResponse2 = TestUtils.clone(authenticateResponse);

        assertEquals(authenticateResponse, authenticateResponse2);
        assertEquals(authenticateResponse.getRequestId(), authenticateResponse2.getRequestId());
    }
}