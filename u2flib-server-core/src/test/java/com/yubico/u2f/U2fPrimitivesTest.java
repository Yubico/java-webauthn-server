/*
 * Copyright 2014 Yubico.
 * Copyright 2014 Google Inc. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */

package com.yubico.u2f;

import com.google.common.collect.ImmutableSet;
import com.yubico.u2f.data.DeviceRegistration;
import com.yubico.u2f.data.messages.AuthenticateRequest;
import com.yubico.u2f.data.messages.AuthenticateResponse;
import com.yubico.u2f.data.messages.RegisterRequest;
import com.yubico.u2f.data.messages.RegisterResponse;
import com.yubico.u2f.exceptions.U2fBadInputException;
import com.yubico.u2f.testdata.AcmeKey;
import com.yubico.u2f.testdata.TestVectors;
import org.junit.Before;
import org.junit.Test;

import java.util.HashSet;
import java.util.Set;

import static com.yubico.u2f.testdata.GnubbyKey.ATTESTATION_CERTIFICATE;
import static com.yubico.u2f.testdata.TestVectors.*;
import static org.junit.Assert.assertEquals;

public class U2fPrimitivesTest {
    final HashSet<String> allowedOrigins = new HashSet<String>();
    U2fPrimitives u2f = new U2fPrimitives();

    @Before
    public void setup() throws Exception {
        allowedOrigins.add("http://example.com");
    }

    @Test
    public void finishRegistration() throws Exception {
        RegisterRequest registerRequest = new RegisterRequest(SERVER_CHALLENGE_REGISTER_BASE64, APP_ID_ENROLL);

        u2f.finishRegistration(registerRequest, new RegisterResponse(TestVectors.REGISTRATION_DATA_BASE64, CLIENT_DATA_REGISTRATION_BASE64), TRUSTED_DOMAINS);
    }

    @Test
    public void finishRegistration2() throws Exception {
        RegisterRequest registerRequest = new RegisterRequest(SERVER_CHALLENGE_REGISTER_BASE64, APP_ID_ENROLL);

        DeviceRegistration deviceRegistration = u2f.finishRegistration(registerRequest, new RegisterResponse(AcmeKey.REGISTRATION_DATA_BASE64, AcmeKey.CLIENT_DATA_BASE64), TRUSTED_DOMAINS);

        assertEquals(new DeviceRegistration(AcmeKey.KEY_HANDLE, AcmeKey.USER_PUBLIC_KEY_B64, AcmeKey.ATTESTATION_CERTIFICATE, 0), deviceRegistration);
    }

    @Test
    public void finishAuthentication() throws Exception {
        AuthenticateRequest authenticateRequest = new AuthenticateRequest(SERVER_CHALLENGE_SIGN_BASE64, APP_ID_SIGN, KEY_HANDLE_BASE64);

        AuthenticateResponse tokenResponse = new AuthenticateResponse(CLIENT_DATA_AUTHENTICATE_BASE64,
                SIGN_RESPONSE_DATA_BASE64, KEY_HANDLE_BASE64);

        u2f.finishAuthentication(authenticateRequest, tokenResponse, new DeviceRegistration(KEY_HANDLE_BASE64, USER_PUBLIC_KEY_AUTHENTICATE_HEX, ATTESTATION_CERTIFICATE, 0), allowedOrigins);
    }


    @Test(expected = U2fBadInputException.class)
    public void finishAuthentication_badOrigin() throws Exception {
        Set<String> allowedOrigins = ImmutableSet.of("some-other-domain.com");
        AuthenticateRequest authentication = new AuthenticateRequest(SERVER_CHALLENGE_SIGN_BASE64,
                APP_ID_SIGN, KEY_HANDLE_BASE64);

        AuthenticateResponse response = new AuthenticateResponse(CLIENT_DATA_AUTHENTICATE_BASE64,
                SIGN_RESPONSE_DATA_BASE64, SERVER_CHALLENGE_SIGN_BASE64);

        u2f.finishAuthentication(authentication, response, new DeviceRegistration(KEY_HANDLE_BASE64, USER_PUBLIC_KEY_AUTHENTICATE_HEX, ATTESTATION_CERTIFICATE, 0), allowedOrigins);
    }

    @Test(expected = IllegalArgumentException.class)
    public void startAuthentication_compromisedDevice() throws Exception {
        RegisterRequest registerRequest = new RegisterRequest(SERVER_CHALLENGE_REGISTER_BASE64, APP_ID_ENROLL);
        DeviceRegistration deviceRegistration = u2f.finishRegistration(registerRequest, new RegisterResponse(AcmeKey.REGISTRATION_DATA_BASE64, AcmeKey.CLIENT_DATA_BASE64), TRUSTED_DOMAINS);
        deviceRegistration.markCompromised();

        u2f.startAuthentication(APP_ID_ENROLL, deviceRegistration);
    }

    @Test(expected = IllegalArgumentException.class)
    public void finishAuthentication_compromisedDevice() throws Exception {
        AuthenticateRequest authenticateRequest = new AuthenticateRequest(SERVER_CHALLENGE_SIGN_BASE64, APP_ID_SIGN, KEY_HANDLE_BASE64);

        AuthenticateResponse tokenResponse = new AuthenticateResponse(CLIENT_DATA_AUTHENTICATE_BASE64,
                SIGN_RESPONSE_DATA_BASE64, KEY_HANDLE_BASE64);

        DeviceRegistration deviceRegistration = new DeviceRegistration(KEY_HANDLE_BASE64, USER_PUBLIC_KEY_AUTHENTICATE_HEX, ATTESTATION_CERTIFICATE, 0);
        deviceRegistration.markCompromised();

        u2f.finishAuthentication(authenticateRequest, tokenResponse, deviceRegistration, allowedOrigins);
    }
}
