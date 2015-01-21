package com.yubico.u2f.data.messages;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.yubico.u2f.TestUtils;
import org.junit.Test;

import static com.yubico.u2f.testdata.TestVectors.*;
import static org.junit.Assert.assertEquals;

public class AuthenticateRequestTest {

    public static final String JSON = "{\"challenge\":\"opsXqUifDriAAmWclinfbS0e-USY0CgyJHe_Otd7z8o\",\"appId\":\"https://gstatic.com/securitykey/a/example.com\",\"keyHandle\":\"KlUt_bdHftZf2EEz-GGWAQsiFbV9p10xW3uej-LjklpgGVUbq2HRZZFlnLrwC0lQ96v-ZmDi4Ab3aGi3ctcMJQ\",\"version\":\"U2F_V2\"}";

    @Test
    public void testGetters() throws Exception {
        AuthenticateRequest authenticateRequest = new AuthenticateRequest(SERVER_CHALLENGE_SIGN_BASE64, APP_ID_SIGN, KEY_HANDLE_BASE64);
        assertEquals(SERVER_CHALLENGE_SIGN_BASE64, authenticateRequest.getChallenge());
        assertEquals(APP_ID_SIGN, authenticateRequest.getAppId());
        assertEquals(KEY_HANDLE_BASE64, authenticateRequest.getKeyHandle());
    }

    @Test
    public void testToAndFromJson() throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();
        AuthenticateRequest authenticateRequest = AuthenticateRequest.fromJson(JSON);
        AuthenticateRequest authenticateRequest2 = objectMapper.readValue(authenticateRequest.toJson(), AuthenticateRequest.class);

        assertEquals(authenticateRequest.getRequestId(), authenticateRequest2.getRequestId());
        assertEquals(authenticateRequest, authenticateRequest2);
        assertEquals(authenticateRequest.toJson(), objectMapper.writeValueAsString(authenticateRequest));
    }

    @Test
    public void testJavaSerializer() throws Exception {
        AuthenticateRequest authenticateRequest = AuthenticateRequest.fromJson(JSON);
        AuthenticateRequest authenticateRequest2 = TestUtils.clone(authenticateRequest);

        assertEquals(authenticateRequest.getRequestId(), authenticateRequest2.getRequestId());
        assertEquals(authenticateRequest, authenticateRequest2);
    }
}