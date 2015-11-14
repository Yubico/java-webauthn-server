package com.yubico.u2f;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.yubico.u2f.data.DeviceRegistration;
import com.yubico.u2f.data.messages.AuthenticateRequest;
import com.yubico.u2f.data.messages.AuthenticateRequestData;
import com.yubico.u2f.data.messages.AuthenticateResponse;
import com.yubico.u2f.exceptions.DeviceCompromisedException;
import com.yubico.u2f.exceptions.NoEligibleDevicesException;
import com.yubico.u2f.exceptions.U2fBadInputException;
import org.junit.Test;

import static com.yubico.u2f.testdata.GnubbyKey.ATTESTATION_CERTIFICATE;
import static com.yubico.u2f.testdata.TestVectors.*;
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

    @Test(expected = DeviceCompromisedException.class)
    public void finishAuthentication_compromisedDevice() throws Exception {
        DeviceRegistration deviceRegistration = new DeviceRegistration(KEY_HANDLE_BASE64, USER_PUBLIC_KEY_AUTHENTICATE_HEX, ATTESTATION_CERTIFICATE, 0);

        AuthenticateRequest request = new AuthenticateRequest(SERVER_CHALLENGE_SIGN_BASE64,
                APP_ID_SIGN, KEY_HANDLE_BASE64);

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

        AuthenticateRequest request = new AuthenticateRequest(SERVER_CHALLENGE_SIGN_BASE64,
                APP_ID_SIGN, KEY_HANDLE_BASE64);

        AuthenticateResponse tokenResponse = new AuthenticateResponse(CLIENT_DATA_AUTHENTICATE_BASE64,
                SIGN_RESPONSE_DATA_BASE64, KEY_HANDLE_BASE64);

        AuthenticateRequestData authenticateRequest = mock(AuthenticateRequestData.class);
        when(authenticateRequest.getAuthenticateRequest(tokenResponse)).thenReturn(request);

        u2f.finishAuthentication(authenticateRequest, tokenResponse, ImmutableList.of(deviceRegistration), ImmutableSet.of("https://wrongfacet.com"));
    }
}
