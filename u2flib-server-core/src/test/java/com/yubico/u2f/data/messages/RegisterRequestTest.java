package com.yubico.u2f.data.messages;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.yubico.u2f.TestUtils;
import org.junit.Test;

import static com.yubico.u2f.testdata.TestVectors.APP_ID_ENROLL;
import static com.yubico.u2f.testdata.TestVectors.SERVER_CHALLENGE_REGISTER_BASE64;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class RegisterRequestTest {

    public static final String JSON = "{\"challenge\":\"vqrS6WXDe1JUs5_c3i4-LkKIHRr-3XVb3azuA5TifHo\",\"appId\":\"http://example.com\",\"version\":\"U2F_V2\"}";

    @Test
    public void testGetters() throws Exception {
        RegisterRequest registerRequest = new RegisterRequest(SERVER_CHALLENGE_REGISTER_BASE64, APP_ID_ENROLL);
        assertEquals(SERVER_CHALLENGE_REGISTER_BASE64, registerRequest.getChallenge());
        assertEquals(APP_ID_ENROLL, registerRequest.getAppId());
        assertNotNull(SERVER_CHALLENGE_REGISTER_BASE64, registerRequest.getRequestId());
    }

    @Test
    public void testToAndFromJson() throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();
        RegisterRequest registerRequest = RegisterRequest.fromJson(JSON);
        RegisterRequest registerRequest2 = objectMapper.readValue(registerRequest.toJson(), RegisterRequest.class);

        assertEquals(registerRequest.getRequestId(), registerRequest2.getRequestId());
        assertEquals(registerRequest.getChallenge(), registerRequest2.getChallenge());
        assertEquals(registerRequest.getAppId(), registerRequest2.getAppId());
        assertEquals(registerRequest.toJson(), objectMapper.writeValueAsString(registerRequest));
    }

    @Test
    public void testJavaSerializer() throws Exception {
        RegisterRequest registerRequest = RegisterRequest.fromJson(JSON);
        RegisterRequest registerRequest2 = TestUtils.clone(registerRequest);

        assertEquals(registerRequest, registerRequest2);
    }
}