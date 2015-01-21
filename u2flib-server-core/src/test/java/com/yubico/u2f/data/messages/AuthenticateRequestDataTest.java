package com.yubico.u2f.data.messages;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Iterables;
import com.yubico.u2f.TestUtils;
import com.yubico.u2f.U2fPrimitives;
import com.yubico.u2f.crypto.ChallengeGenerator;
import com.yubico.u2f.data.DeviceRegistration;
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding;
import org.junit.Test;

import static com.yubico.u2f.testdata.TestVectors.APP_ID_SIGN;
import static com.yubico.u2f.testdata.TestVectors.SERVER_CHALLENGE_SIGN_BASE64;
import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class AuthenticateRequestDataTest {
    public static final String JSON = "{\"authenticateRequests\":[{\"challenge\":\"opsXqUifDriAAmWclinfbS0e-USY0CgyJHe_Otd7z8o\",\"appId\":\"https://gstatic.com/securitykey/a/example.com\",\"keyHandle\":\"KlUt_bdHftZf2EEz-GGWAQsiFbV9p10xW3uej-LjklpgGVUbq2HRZZFlnLrwC0lQ96v-ZmDi4Ab3aGi3ctcMJQ\",\"version\":\"U2F_V2\",\"requestId\":\"opsXqUifDriAAmWclinfbS0e-USY0CgyJHe_Otd7z8o\"}]}";

    @Test
    public void testGetters() throws Exception {
        DeviceRegistration device = mock(DeviceRegistration.class);
        U2fPrimitives primitives = mock(U2fPrimitives.class);
        ChallengeGenerator challengeGenerator = mock(ChallengeGenerator.class);

        byte[] challenge = U2fB64Encoding.decode(SERVER_CHALLENGE_SIGN_BASE64);
        when(challengeGenerator.generateChallenge()).thenReturn(challenge);
        AuthenticateRequest authenticateRequest = AuthenticateRequest.fromJson(AuthenticateRequestTest.JSON);
        when(primitives.startAuthentication(APP_ID_SIGN, device, challenge)).thenReturn(authenticateRequest);

        AuthenticateRequestData requestData = new AuthenticateRequestData(APP_ID_SIGN, ImmutableList.of(device), primitives, challengeGenerator);

        assertEquals(SERVER_CHALLENGE_SIGN_BASE64, requestData.getRequestId());
        AuthenticateRequest authenticateRequest2 = Iterables.getOnlyElement(requestData.getAuthenticateRequests());
        assertEquals(authenticateRequest, authenticateRequest);
    }

    @Test
    public void testToAndFromJson() throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();
        AuthenticateRequestData requestData = AuthenticateRequestData.fromJson(JSON);
        AuthenticateRequestData requestData2 = objectMapper.readValue(requestData.toJson(), AuthenticateRequestData.class);

        assertEquals(requestData.getRequestId(), requestData2.getRequestId());
        assertEquals(requestData, requestData2);
        assertEquals(requestData.toJson(), objectMapper.writeValueAsString(requestData));
    }

    @Test
    public void testJavaSerializer() throws Exception {
        AuthenticateRequestData requestData = AuthenticateRequestData.fromJson(JSON);
        AuthenticateRequestData requestData2 = TestUtils.clone(requestData);

        assertEquals(requestData.getRequestId(), requestData2.getRequestId());
        assertEquals(requestData, requestData2);
    }
}