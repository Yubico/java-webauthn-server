package com.yubico.u2f;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.yubico.u2f.data.DeviceRegistration;
import com.yubico.u2f.data.messages.AuthenticateRequest;
import com.yubico.u2f.data.messages.AuthenticateRequestData;
import com.yubico.u2f.data.messages.AuthenticateResponse;
import com.yubico.u2f.data.messages.RegisterRequestData;
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
}
