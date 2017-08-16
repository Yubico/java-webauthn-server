package com.yubico.u2f.data.messages;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.common.collect.ImmutableList;
import com.google.common.collect.Iterables;
import com.yubico.u2f.TestUtils;
import com.yubico.u2f.U2fPrimitives;
import com.yubico.u2f.crypto.ChallengeGenerator;
import com.yubico.u2f.crypto.RandomChallengeGenerator;
import com.yubico.u2f.data.DeviceRegistration;
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding;
import org.junit.Test;

import static com.yubico.u2f.testdata.TestVectors.APP_ID_ENROLL;
import static com.yubico.u2f.testdata.TestVectors.SERVER_CHALLENGE_REGISTER_BASE64;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class RegisterRequestDataTest {
    public static final String KEY_HANDLE = "KlUt_bdHftZf2EEz-GGWAQsiFbV9p10xW3uej-LjklpgGVUbq2HRZZFlnLrwC0lQ96v-ZmDi4Ab3aGi3ctcMJQ";
    public static final String JSON = "{\"registeredKeys\":[{\"keyHandle\":\"" + KEY_HANDLE + "\",\"version\":\"U2F_V2\"}],\"registerRequests\":[{\"challenge\":\"vqrS6WXDe1JUs5_c3i4-LkKIHRr-3XVb3azuA5TifHo\",\"appId\":\"http://example.com\",\"version\":\"U2F_V2\"}]}";

    @Test
    public void testGetters() throws Exception {
        DeviceRegistration device = mock(DeviceRegistration.class);
        when(device.getKeyHandle()).thenReturn(KEY_HANDLE);

        U2fPrimitives primitives = mock(U2fPrimitives.class);
        ChallengeGenerator challengeGenerator = mock(ChallengeGenerator.class);

        byte[] challenge = U2fB64Encoding.decode(SERVER_CHALLENGE_REGISTER_BASE64);
        when(challengeGenerator.generateChallenge()).thenReturn(challenge);
        SignRequest signRequest = SignRequest.fromJson(SignRequestTest.JSON);
        when(primitives.startSignature(APP_ID_ENROLL, device)).thenReturn(signRequest);
        RegisterRequest registerRequest = RegisterRequest.fromJson(RegisterRequestTest.JSON);
        when(primitives.startRegistration(APP_ID_ENROLL, challenge)).thenReturn(registerRequest);

        RegisterRequestData requestData = new RegisterRequestData(APP_ID_ENROLL, ImmutableList.of(device), primitives, challengeGenerator);

        assertEquals(SERVER_CHALLENGE_REGISTER_BASE64, requestData.getRequestId());
        RegisterRequest registerRequest2 = Iterables.getOnlyElement(requestData.getRegisterRequests());
        assertEquals(registerRequest, registerRequest2);
    }

    @Test
    public void testToAndFromJson() throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();
        RegisterRequestData requestData = RegisterRequestData.fromJson(JSON);
        RegisterRequestData requestData2 = objectMapper.readValue(requestData.toJson(), RegisterRequestData.class);

        assertEquals(requestData, requestData2);
        assertEquals(requestData.getRequestId(), requestData2.getRequestId());
        assertEquals(requestData.toJson(), objectMapper.writeValueAsString(requestData));
        assertEquals(KEY_HANDLE, requestData.getRegisteredKeys().get(0).getKeyHandle());
    }

    @Test
    public void testJavaSerializer() throws Exception {
        RegisterRequestData requestData = RegisterRequestData.fromJson(JSON);
        RegisterRequestData requestData2 = TestUtils.clone(requestData);

        assertEquals(requestData, requestData2);
        assertEquals(requestData.getRequestId(), requestData2.getRequestId());
    }

    private DeviceRegistration mockDevice(final String keyHandle, boolean compromised) {
        DeviceRegistration device = mock(DeviceRegistration.class);
        when(device.getKeyHandle()).thenReturn(keyHandle);
        when(device.isCompromised()).thenReturn(compromised);
        return device;
    }

    @Test
    public void testConstructorAddsOneRegisteredKeyForEachGivenNonCompromisedDeviceRegistration() {
        DeviceRegistration good1 = mockDevice("A", false);
        DeviceRegistration good2 = mockDevice("B", false);
        DeviceRegistration bad1 = mockDevice("C", true);
        DeviceRegistration bad2 = mockDevice("D", true);

        RegisterRequestData result = new RegisterRequestData(
            "AppId",
            ImmutableList.of(good1, bad1, bad2, good2),
            new U2fPrimitives(),
            new RandomChallengeGenerator()
        );

        assertEquals(2, result.getRegisteredKeys().size());
        assertTrue(result.getRegisteredKeys().contains(new RegisteredKey(U2fPrimitives.U2F_VERSION, "A", null, null)));
        assertTrue(result.getRegisteredKeys().contains(new RegisteredKey(U2fPrimitives.U2F_VERSION, "B", null, null)));
    }

}
