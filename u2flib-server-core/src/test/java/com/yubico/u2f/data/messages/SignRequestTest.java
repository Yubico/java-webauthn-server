package com.yubico.u2f.data.messages;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.yubico.u2f.TestUtils;
import org.junit.Test;

import static com.yubico.u2f.testdata.TestVectors.*;
import static org.junit.Assert.assertEquals;

public class SignRequestTest {

    public static final String JSON = "{\"challenge\":\"opsXqUifDriAAmWclinfbS0e-USY0CgyJHe_Otd7z8o\",\"appId\":\"https://gstatic.com/securitykey/a/example.com\",\"keyHandle\":\"KlUt_bdHftZf2EEz-GGWAQsiFbV9p10xW3uej-LjklpgGVUbq2HRZZFlnLrwC0lQ96v-ZmDi4Ab3aGi3ctcMJQ\",\"version\":\"U2F_V2\"}";

    @Test
    public void testGetters() throws Exception {
        SignRequest signRequest = SignRequest.builder().challenge(SERVER_CHALLENGE_SIGN_BASE64).appId(APP_ID_SIGN).keyHandle(KEY_HANDLE_BASE64).build();
        assertEquals(SERVER_CHALLENGE_SIGN_BASE64, signRequest.getChallenge());
        assertEquals(SERVER_CHALLENGE_SIGN_BASE64, signRequest.getRequestId());
        assertEquals(APP_ID_SIGN, signRequest.getAppId());
        assertEquals(KEY_HANDLE_BASE64, signRequest.getKeyHandle());
    }

    @Test
    public void testToAndFromJson() throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();
        SignRequest signRequest = SignRequest.fromJson(JSON);
        SignRequest signRequest2 = objectMapper.readValue(signRequest.toJson(), SignRequest.class);

        assertEquals(signRequest.getRequestId(), signRequest2.getRequestId());
        assertEquals(signRequest, signRequest2);
        assertEquals(signRequest.toJson(), objectMapper.writeValueAsString(signRequest));
    }

    @Test
    public void testJavaSerializer() throws Exception {
        SignRequest signRequest = SignRequest.fromJson(JSON);
        SignRequest signRequest2 = TestUtils.clone(signRequest);

        assertEquals(signRequest.getRequestId(), signRequest2.getRequestId());
        assertEquals(signRequest, signRequest2);
    }
}
