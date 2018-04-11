package com.yubico.u2f.data.messages;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.yubico.u2f.TestUtils;
import com.yubico.u2f.exceptions.U2fBadInputException;
import org.junit.Test;

import static com.yubico.u2f.testdata.TestVectors.*;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

public class SignResponseTest {
    public static final String JSON = "{\"clientData\":\"eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZ2V0QXNzZXJ0aW9uIiwiY2hhbGxlbmdlIjoib3BzWHFVaWZEcmlBQW1XY2xpbmZiUzBlLVVTWTBDZ3lKSGVfT3RkN3o4byIsImNpZF9wdWJrZXkiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJIelF3bGZYWDdRNFM1TXRDQ25aVU5CdzNSTXpQTzl0T3lXakJxUmw0dEo4IiwieSI6IlhWZ3VHRkxJWngxZlhnM3dOcWZkYm43NWhpNC1fNy1CeGhNbGp3NDJIdDQifSwib3JpZ2luIjoiaHR0cDovL2V4YW1wbGUuY29tIn0\",\"signatureData\":\"\",\"keyHandle\":\"KlUt_bdHftZf2EEz-GGWAQsiFbV9p10xW3uej-LjklpgGVUbq2HRZZFlnLrwC0lQ96v-ZmDi4Ab3aGi3ctcMJQ\"}";

    @Test
    public void testGetters() throws Exception {
        SignResponse signResponse = new SignResponse(CLIENT_DATA_SIGN_BASE64, "", KEY_HANDLE_BASE64);

        assertEquals(CLIENT_DATA_SIGN, signResponse.getClientData().toString());
        assertEquals(KEY_HANDLE_BASE64, signResponse.getKeyHandle());
    }

    @Test
    public void testToAndFromJson() throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();
        SignResponse signResponse = SignResponse.fromJson(JSON);
        SignResponse signResponse2 = objectMapper.readValue(signResponse.toJson(), SignResponse.class);

        assertEquals(signResponse, signResponse2);
        assertEquals(signResponse.getRequestId(), signResponse2.getRequestId());
        assertEquals(signResponse.toJson(), objectMapper.writeValueAsString(signResponse));
    }

    @Test
    public void testJavaSerializer() throws Exception {
        SignResponse signResponse = SignResponse.fromJson(JSON);
        SignResponse signResponse2 = TestUtils.clone(signResponse);

        assertEquals(signResponse, signResponse2);
        assertEquals(signResponse.getRequestId(), signResponse2.getRequestId());
    }

    @Test(expected = IllegalArgumentException.class)
    public void fromJsonDetectsTooLongJsonContent() throws U2fBadInputException {
        SignResponse.fromJson(makeLongJson(20000));
        fail("fromJson did not detect too long JSON content.");
    }

    @Test
    public void fromJsonAllowsShortJsonContent() throws U2fBadInputException {
        assertNotNull(SignResponse.fromJson(makeLongJson(19999)));
    }

    private String makeLongJson(int totalLength) {
        final String jsonPrefix = "{\"clientData\":\"eyJ0eXAiOiJuYXZpZ2F0b3IuaWQuZ2V0QXNzZXJ0aW9uIiwiY2hhbGxlbmdlIjoib3BzWHFVaWZEcmlBQW1XY2xpbmZiUzBlLVVTWTBDZ3lKSGVfT3RkN3o4byIsImNpZF9wdWJrZXkiOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJIelF3bGZYWDdRNFM1TXRDQ25aVU5CdzNSTXpQTzl0T3lXakJxUmw0dEo4IiwieSI6IlhWZ3VHRkxJWngxZlhnM3dOcWZkYm43NWhpNC1fNy1CeGhNbGp3NDJIdDQifSwib3JpZ2luIjoiaHR0cDovL2V4YW1wbGUuY29tIn0\",\"signatureData\":\"\",\"keyHandle\":\"";
        final String jsonSuffix = "\"}";
        final int infixLength = totalLength - jsonPrefix.length() - jsonSuffix.length();
        return jsonPrefix + String.format("%0" + infixLength + "d", 0).replace("0", "a") + jsonSuffix;
    }

}
