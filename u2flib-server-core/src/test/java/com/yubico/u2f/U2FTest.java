package com.yubico.u2f;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.yubico.u2f.data.DeviceRegistration;
import com.yubico.u2f.data.messages.AuthenticateRequest;
import com.yubico.u2f.data.messages.AuthenticateRequestData;
import com.yubico.u2f.data.messages.AuthenticateResponse;
import com.yubico.u2f.data.messages.RegisterRequest;
import com.yubico.u2f.data.messages.RegisterRequestData;
import com.yubico.u2f.data.messages.RegisterResponse;
import com.yubico.u2f.data.messages.RegisteredKey;
import com.yubico.u2f.exceptions.DeviceCompromisedException;
import com.yubico.u2f.exceptions.NoEligibleDevicesException;
import com.yubico.u2f.exceptions.U2fBadConfigurationException;
import com.yubico.u2f.exceptions.U2fBadInputException;
import org.junit.Test;

import static com.yubico.u2f.testdata.GnubbyKey.ATTESTATION_CERTIFICATE;
import static com.yubico.u2f.testdata.TestVectors.*;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class U2FTest {
    U2F u2f = U2F.withoutAppIdValidation();

    @Test
    public void startRegistration_compromisedDevice() throws Exception {
        DeviceRegistration deviceRegistration = new DeviceRegistration(KEY_HANDLE_BASE64, USER_PUBLIC_KEY_AUTHENTICATE_HEX, ATTESTATION_CERTIFICATE, 0);
        deviceRegistration.markCompromised();
        u2f.startRegistration(APP_ID_ENROLL, ImmutableList.of(deviceRegistration));
    }

    @Test(expected = NoEligibleDevicesException.class)
    public void startAuthentication_compromisedDevices() throws Exception {
        DeviceRegistration deviceRegistration = new DeviceRegistration(KEY_HANDLE_BASE64, USER_PUBLIC_KEY_AUTHENTICATE_HEX, ATTESTATION_CERTIFICATE, 0);
        deviceRegistration.markCompromised();
        u2f.startAuthentication(APP_ID_ENROLL, ImmutableList.of(deviceRegistration));
    }

    @Test(expected = U2fBadConfigurationException.class)
    public void defaultConstructedU2FstartRegistrationShouldRefuseInvalidAppId() {
        DeviceRegistration deviceRegistration = new DeviceRegistration(KEY_HANDLE_BASE64, USER_PUBLIC_KEY_AUTHENTICATE_HEX, ATTESTATION_CERTIFICATE, 0);
        deviceRegistration.markCompromised();
        new U2F().startRegistration("example.com", ImmutableList.of(deviceRegistration));

        fail("startRegistration did not refuse an invalid app ID.");
    }

    @Test
    public void startRegistrationShouldReturnAChallenge() {
        DeviceRegistration deviceRegistration = new DeviceRegistration(KEY_HANDLE_BASE64, USER_PUBLIC_KEY_AUTHENTICATE_HEX, ATTESTATION_CERTIFICATE, 0);
        RegisterRequestData data = u2f.startRegistration("example.com", ImmutableList.of(deviceRegistration));

        assertEquals(1, data.getRegisterRequests().size());
        assertNotNull(data.getRegisterRequests().get(0).getChallenge());
    }

    @Test(expected = U2fBadConfigurationException.class)
    public void defaultConstructedU2FstartAuthenticationShouldRefuseInvalidAppId() throws Exception {
        DeviceRegistration deviceRegistration = new DeviceRegistration(KEY_HANDLE_BASE64, USER_PUBLIC_KEY_AUTHENTICATE_HEX, ATTESTATION_CERTIFICATE, 0);
        deviceRegistration.markCompromised();
        new U2F().startAuthentication("example.com", ImmutableList.of(deviceRegistration));

        fail("startRegistration did not refuse an invalid app ID.");
    }

    @Test
    public void startAuthenticationShouldReturnAChallenge() throws Exception {
        DeviceRegistration deviceRegistration = new DeviceRegistration(KEY_HANDLE_BASE64, USER_PUBLIC_KEY_AUTHENTICATE_HEX, ATTESTATION_CERTIFICATE, 0);
        AuthenticateRequestData data = u2f.startAuthentication("example.com", ImmutableList.of(deviceRegistration));

        assertEquals(1, data.getAuthenticateRequests().size());
        assertNotNull(data.getAuthenticateRequests().get(0).getChallenge());
    }

    @Test(expected = DeviceCompromisedException.class)
    public void finishAuthentication_compromisedDevice() throws Exception {
        DeviceRegistration deviceRegistration = new DeviceRegistration(KEY_HANDLE_BASE64, USER_PUBLIC_KEY_AUTHENTICATE_HEX, ATTESTATION_CERTIFICATE, 0);

        AuthenticateRequest request = AuthenticateRequest.builder()
            .challenge(SERVER_CHALLENGE_SIGN_BASE64)
            .appId(APP_ID_SIGN)
            .keyHandle(KEY_HANDLE_BASE64)
            .build();

        AuthenticateResponse tokenResponse = new AuthenticateResponse(CLIENT_DATA_AUTHENTICATE_BASE64,
                SIGN_RESPONSE_DATA_BASE64, KEY_HANDLE_BASE64);

        AuthenticateRequestData authenticateRequest = mock(AuthenticateRequestData.class);
        when(authenticateRequest.getAuthenticateRequest(tokenResponse)).thenReturn(request);

        deviceRegistration.markCompromised();
        u2f.finishAuthentication(authenticateRequest, tokenResponse, ImmutableList.of(deviceRegistration));
    }

    @Test(expected = U2fBadInputException.class)
    public void finishAuthentication_invalidFacet() throws Exception {
        DeviceRegistration deviceRegistration = new DeviceRegistration(KEY_HANDLE_BASE64, USER_PUBLIC_KEY_AUTHENTICATE_HEX, ATTESTATION_CERTIFICATE, 0);

        AuthenticateRequest request = AuthenticateRequest.builder()
            .challenge(SERVER_CHALLENGE_SIGN_BASE64)
            .appId(APP_ID_SIGN)
            .keyHandle(KEY_HANDLE_BASE64)
            .build();

        AuthenticateResponse tokenResponse = new AuthenticateResponse(CLIENT_DATA_AUTHENTICATE_BASE64,
                SIGN_RESPONSE_DATA_BASE64, KEY_HANDLE_BASE64);

        AuthenticateRequestData authenticateRequest = mock(AuthenticateRequestData.class);
        when(authenticateRequest.getAuthenticateRequest(tokenResponse)).thenReturn(request);

        u2f.finishAuthentication(authenticateRequest, tokenResponse, ImmutableList.of(deviceRegistration), ImmutableSet.of("https://wrongfacet.com"));
    }


    @Test
    public void finishRegistrationShouldReturnAMatchedDevice() throws Exception {
        DeviceRegistration deviceRegistration = new DeviceRegistration(KEY_HANDLE_BASE64, USER_PUBLIC_KEY_AUTHENTICATE_HEX, ATTESTATION_CERTIFICATE, 0);
        DeviceRegistration deviceRegistration2 = new DeviceRegistration(KEY_HANDLE_BASE64, USER_PUBLIC_KEY_AUTHENTICATE_HEX, ATTESTATION_CERTIFICATE, 0);

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
    public void finishAuthenticationShouldReturnAMatchedDevice() throws Exception {
        DeviceRegistration deviceRegistration = new DeviceRegistration(KEY_HANDLE_BASE64, USER_PUBLIC_KEY_AUTHENTICATE_HEX, ATTESTATION_CERTIFICATE, 0);
        DeviceRegistration deviceRegistration2 = new DeviceRegistration(KEY_HANDLE_BASE64, USER_PUBLIC_KEY_AUTHENTICATE_HEX, ATTESTATION_CERTIFICATE, 0);

        AuthenticateRequest request = AuthenticateRequest.builder()
            .challenge(SERVER_CHALLENGE_SIGN_BASE64)
            .appId(APP_ID_SIGN)
            .keyHandle(KEY_HANDLE_BASE64)
            .build();

        AuthenticateResponse tokenResponse = new AuthenticateResponse(CLIENT_DATA_AUTHENTICATE_BASE64,
            SIGN_RESPONSE_DATA_BASE64, KEY_HANDLE_BASE64);

        AuthenticateRequestData authenticateRequest = new AuthenticateRequestData(
            APP_ID_SIGN,
            SERVER_CHALLENGE_SIGN_BASE64,
            ImmutableList.of(request)
        );

        DeviceRegistration device = u2f.finishAuthentication(authenticateRequest, tokenResponse, ImmutableList.of(deviceRegistration), ImmutableSet.of(APP_ID_ENROLL));
        DeviceRegistration overloadDevice = u2f.finishAuthentication(authenticateRequest, tokenResponse, ImmutableList.of(deviceRegistration2));

        assertEquals(KEY_HANDLE_BASE64, device.getKeyHandle());
        assertEquals(device, overloadDevice);
    }

}
