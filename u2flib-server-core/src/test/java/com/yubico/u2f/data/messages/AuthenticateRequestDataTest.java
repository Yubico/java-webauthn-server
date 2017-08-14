package com.yubico.u2f.data.messages;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Iterables;
import com.yubico.u2f.TestUtils;
import com.yubico.u2f.U2fPrimitives;
import com.yubico.u2f.crypto.ChallengeGenerator;
import com.yubico.u2f.data.DeviceRegistration;
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding;
import com.yubico.u2f.exceptions.NoEligibleDevicesException;
import org.junit.Test;

import static com.yubico.u2f.testdata.TestVectors.APP_ID_SIGN;
import static com.yubico.u2f.testdata.TestVectors.SERVER_CHALLENGE_SIGN_BASE64;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class AuthenticateRequestDataTest {
    public static final String JSON = "{\"authenticateRequests\":[{\"challenge\":\"opsXqUifDriAAmWclinfbS0e-USY0CgyJHe_Otd7z8o\",\"appId\":\"https://gstatic.com/securitykey/a/example.com\",\"keyHandle\":\"KlUt_bdHftZf2EEz-GGWAQsiFbV9p10xW3uej-LjklpgGVUbq2HRZZFlnLrwC0lQ96v-ZmDi4Ab3aGi3ctcMJQ\",\"version\":\"U2F_V2\"}]}";

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
        assertEquals(authenticateRequest, authenticateRequest2);
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

    @Test(expected = IllegalArgumentException.class)
    public void getAuthenticateChecksResponseId() throws Exception {
        AuthenticateRequestData requestData = AuthenticateRequestData.fromJson(JSON);

        final String clientDataJson = "{\"typ\":\"navigator.id.getAssertion\",\"challenge\":\"OpsXqUifDriAAmWclinfbS0e-USY0CgyJHe_Otd7z8o\",\"cid_pubkey\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"HzQwlfXX7Q4S5MtCCnZUNBw3RMzPO9tOyWjBqRl4tJ8\",\"y\":\"XVguGFLIZx1fXg3wNqfdbn75hi4-_7-BxhMljw42Ht4\"},\"origin\":\"http://example.com\"}";
        final String authenticateResponseJson = "{\"clientData\":\"" + U2fB64Encoding.encode(clientDataJson.getBytes("UTF-8")) + "\",\"signatureData\":\"\",\"keyHandle\":\"KlUt_bdHftZf2EEz-GGWAQsiFbV9p10xW3uej-LjklpgGVUbq2HRZZFlnLrwC0lQ96v-ZmDi4Ab3aGi3ctcMJQ\"}";
        requestData.getAuthenticateRequest(AuthenticateResponse.fromJson(authenticateResponseJson));

        fail("getAuthenticateRequest did not detect wrong request ID.");
    }

    @Test
    public void testFailureModesAreIdentifiable() throws Exception {

        byte[] challenge = U2fB64Encoding.decode(SERVER_CHALLENGE_SIGN_BASE64);
        ChallengeGenerator challengeGenerator = mock(ChallengeGenerator.class);
        when(challengeGenerator.generateChallenge()).thenReturn(challenge);

        try {
            new AuthenticateRequestData(APP_ID_SIGN, ImmutableList.<DeviceRegistration>of(), mock(U2fPrimitives.class), challengeGenerator);
        } catch (NoEligibleDevicesException e) {
            assertFalse(e.hasDevices());
        }

        DeviceRegistration compromisedDevice = mock(DeviceRegistration.class);
        when(compromisedDevice.isCompromised()).thenReturn(true);

        try {
            new AuthenticateRequestData(APP_ID_SIGN, ImmutableList.of(compromisedDevice), mock(U2fPrimitives.class), challengeGenerator);
        } catch (NoEligibleDevicesException e) {
            assertTrue(e.hasDevices());
        }

    }

}
