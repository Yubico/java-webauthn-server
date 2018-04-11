package com.yubico.u2f;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.yubico.u2f.data.DeviceRegistration;
import com.yubico.u2f.data.messages.SignRequest;
import com.yubico.u2f.data.messages.SignRequestData;
import com.yubico.u2f.data.messages.SignResponse;
import com.yubico.u2f.data.messages.RegisterRequest;
import com.yubico.u2f.data.messages.RegisterRequestData;
import com.yubico.u2f.data.messages.RegisterResponse;
import com.yubico.u2f.data.messages.RegisteredKey;
import com.yubico.u2f.exceptions.DeviceCompromisedException;
import com.yubico.u2f.exceptions.NoEligibleDevicesException;
import com.yubico.u2f.exceptions.U2fBadConfigurationException;
import com.yubico.u2f.exceptions.U2fBadInputException;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import static com.yubico.u2f.testdata.GnubbyKey.ATTESTATION_CERTIFICATE;
import static com.yubico.u2f.testdata.TestVectors.*;
import static org.hamcrest.core.Is.isA;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class U2FTest {
    U2F u2f = U2F.withoutAppIdValidation();

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Test
    public void startRegistration_compromisedDevice() throws Exception {
        DeviceRegistration deviceRegistration = new DeviceRegistration(KEY_HANDLE_BASE64, USER_PUBLIC_KEY_SIGN_HEX, ATTESTATION_CERTIFICATE, 0);
        deviceRegistration.markCompromised();
        u2f.startRegistration(APP_ID_ENROLL, ImmutableList.of(deviceRegistration));
    }

    @Test(expected = NoEligibleDevicesException.class)
    public void startSignature_compromisedDevices() throws Exception {
        DeviceRegistration deviceRegistration = new DeviceRegistration(KEY_HANDLE_BASE64, USER_PUBLIC_KEY_SIGN_HEX, ATTESTATION_CERTIFICATE, 0);
        deviceRegistration.markCompromised();
        u2f.startSignature(APP_ID_ENROLL, ImmutableList.of(deviceRegistration));
    }

    @Test(expected = U2fBadConfigurationException.class)
    public void defaultConstructedU2FstartRegistrationShouldRefuseInvalidAppId() throws U2fBadInputException, U2fBadConfigurationException {
        DeviceRegistration deviceRegistration = new DeviceRegistration(KEY_HANDLE_BASE64, USER_PUBLIC_KEY_SIGN_HEX, ATTESTATION_CERTIFICATE, 0);
        deviceRegistration.markCompromised();
        new U2F().startRegistration("example.com", ImmutableList.of(deviceRegistration));

        fail("startRegistration did not refuse an invalid app ID.");
    }

    @Test
    public void startRegistrationShouldReturnARandomChallenge() throws U2fBadInputException, U2fBadConfigurationException {
        DeviceRegistration deviceRegistration = new DeviceRegistration(KEY_HANDLE_BASE64, USER_PUBLIC_KEY_SIGN_HEX, ATTESTATION_CERTIFICATE, 0);
        RegisterRequestData data = u2f.startRegistration("example.com", ImmutableList.of(deviceRegistration));
        RegisterRequestData data2 = u2f.startRegistration("example.com", ImmutableList.of(deviceRegistration));

        assertEquals(1, data.getRegisterRequests().size());
        assertEquals(1, data2.getRegisterRequests().size());
        assertNotEquals(
            "startRegistration must not return the same challenge twice in a row.",
            data.getRegisterRequests().get(0).getChallenge(),
            data2.getRegisterRequests().get(0).getChallenge()
        );
    }

    @Test(expected = U2fBadConfigurationException.class)
    public void defaultConstructedU2FstartSignatureShouldRefuseInvalidAppId() throws Exception {
        DeviceRegistration deviceRegistration = new DeviceRegistration(KEY_HANDLE_BASE64, USER_PUBLIC_KEY_SIGN_HEX, ATTESTATION_CERTIFICATE, 0);
        deviceRegistration.markCompromised();
        new U2F().startSignature("example.com", ImmutableList.of(deviceRegistration));

        fail("startRegistration did not refuse an invalid app ID.");
    }

    @Test
    public void startSignatureShouldReturnARandomChallenge() throws Exception {
        DeviceRegistration deviceRegistration = new DeviceRegistration(KEY_HANDLE_BASE64, USER_PUBLIC_KEY_SIGN_HEX, ATTESTATION_CERTIFICATE, 0);
        SignRequestData data = u2f.startSignature("example.com", ImmutableList.of(deviceRegistration));
        SignRequestData data2 = u2f.startSignature("example.com", ImmutableList.of(deviceRegistration));

        assertEquals(1, data.getSignRequests().size());
        assertNotNull(data.getSignRequests().get(0).getChallenge());
        assertNotEquals(
            "startSignature must not return the same challenge twice in a row.",
            data.getSignRequests().get(0).getChallenge(),
            data2.getSignRequests().get(0).getChallenge()
        );
    }

    @Test(expected = DeviceCompromisedException.class)
    public void finishSignature_compromisedDevice() throws Exception {
        DeviceRegistration deviceRegistration = new DeviceRegistration(KEY_HANDLE_BASE64, USER_PUBLIC_KEY_SIGN_HEX, ATTESTATION_CERTIFICATE, 0);

        SignRequest request = SignRequest.builder()
            .challenge(SERVER_CHALLENGE_SIGN_BASE64)
            .appId(APP_ID_SIGN)
            .keyHandle(KEY_HANDLE_BASE64)
            .build();

        SignResponse tokenResponse = new SignResponse(CLIENT_DATA_SIGN_BASE64,
                SIGN_RESPONSE_DATA_BASE64, KEY_HANDLE_BASE64);

        SignRequestData requestData = mock(SignRequestData.class);
        when(requestData.getSignRequest(tokenResponse)).thenReturn(request);

        deviceRegistration.markCompromised();
        u2f.finishSignature(requestData, tokenResponse, ImmutableList.of(deviceRegistration));
    }

    @Test
    public void finishSignature_invalidFacet() throws Exception {
        expectedException.expectCause(isA(U2fBadInputException.class));

        DeviceRegistration deviceRegistration = new DeviceRegistration(KEY_HANDLE_BASE64, USER_PUBLIC_KEY_SIGN_HEX, ATTESTATION_CERTIFICATE, 0);

        SignRequest request = SignRequest.builder()
            .challenge(SERVER_CHALLENGE_SIGN_BASE64)
            .appId(APP_ID_SIGN)
            .keyHandle(KEY_HANDLE_BASE64)
            .build();

        SignResponse tokenResponse = new SignResponse(CLIENT_DATA_SIGN_BASE64,
                SIGN_RESPONSE_DATA_BASE64, KEY_HANDLE_BASE64);

        SignRequestData requestData = mock(SignRequestData.class);
        when(requestData.getSignRequest(tokenResponse)).thenReturn(request);

        u2f.finishSignature(requestData, tokenResponse, ImmutableList.of(deviceRegistration), ImmutableSet.of("https://wrongfacet.com"));
    }


    @Test
    public void finishRegistrationShouldReturnAMatchedDevice() throws Exception {
        DeviceRegistration deviceRegistration = new DeviceRegistration(KEY_HANDLE_BASE64, USER_PUBLIC_KEY_SIGN_HEX, ATTESTATION_CERTIFICATE, 0);
        DeviceRegistration deviceRegistration2 = new DeviceRegistration(KEY_HANDLE_BASE64, USER_PUBLIC_KEY_SIGN_HEX, ATTESTATION_CERTIFICATE, 0);

        RegisterRequest request = new RegisterRequest(SERVER_CHALLENGE_REGISTER_BASE64, APP_ID_ENROLL);

        RegisterResponse tokenResponse = new RegisterResponse(
            REGISTRATION_DATA_BASE64,
            CLIENT_DATA_REGISTRATION_BASE64
        );

        RegisterRequestData registerRequest = new RegisterRequestData(
            APP_ID_ENROLL,
            ImmutableList.<RegisteredKey>of(),
            ImmutableList.of(request)
        );

        DeviceRegistration device = u2f.finishRegistration(registerRequest, tokenResponse, ImmutableSet.of(APP_ID_ENROLL));
        DeviceRegistration overloadDevice = u2f.finishRegistration(registerRequest, tokenResponse);

        assertEquals(KEY_HANDLE_BASE64, device.getKeyHandle());
        assertEquals(device, overloadDevice);
    }

    @Test
    public void finishSignatureShouldReturnAMatchedDevice() throws Exception {
        DeviceRegistration deviceRegistration = new DeviceRegistration(KEY_HANDLE_BASE64, USER_PUBLIC_KEY_SIGN_HEX, ATTESTATION_CERTIFICATE, 0);
        DeviceRegistration deviceRegistration2 = new DeviceRegistration(KEY_HANDLE_BASE64, USER_PUBLIC_KEY_SIGN_HEX, ATTESTATION_CERTIFICATE, 0);

        SignRequest request = SignRequest.builder()
            .challenge(SERVER_CHALLENGE_SIGN_BASE64)
            .appId(APP_ID_SIGN)
            .keyHandle(KEY_HANDLE_BASE64)
            .build();

        SignResponse tokenResponse = new SignResponse(CLIENT_DATA_SIGN_BASE64,
            SIGN_RESPONSE_DATA_BASE64, KEY_HANDLE_BASE64);

        SignRequestData requestData = new SignRequestData(
            APP_ID_SIGN,
            SERVER_CHALLENGE_SIGN_BASE64,
            ImmutableList.of(request)
        );

        DeviceRegistration device = u2f.finishSignature(requestData, tokenResponse, ImmutableList.of(deviceRegistration), ImmutableSet.of(APP_ID_ENROLL));
        DeviceRegistration overloadDevice = u2f.finishSignature(requestData, tokenResponse, ImmutableList.of(deviceRegistration2));

        assertEquals(KEY_HANDLE_BASE64, device.getKeyHandle());
        assertEquals(device, overloadDevice);
    }

}
