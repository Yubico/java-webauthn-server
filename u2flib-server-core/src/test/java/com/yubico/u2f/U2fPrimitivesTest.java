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
import com.yubico.u2f.data.messages.SignRequest;
import com.yubico.u2f.data.messages.SignResponse;
import com.yubico.u2f.data.messages.RegisterRequest;
import com.yubico.u2f.data.messages.RegisterResponse;
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding;
import com.yubico.u2f.exceptions.U2fAuthenticationException;
import com.yubico.u2f.exceptions.U2fBadInputException;
import com.yubico.u2f.testdata.AcmeKey;
import com.yubico.u2f.testdata.TestVectors;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;

import java.util.HashSet;
import java.util.Set;
import org.junit.rules.ExpectedException;

import static com.yubico.u2f.testdata.GnubbyKey.ATTESTATION_CERTIFICATE;
import static com.yubico.u2f.testdata.TestVectors.*;
import static org.hamcrest.core.Is.isA;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

public class U2fPrimitivesTest {
    final HashSet<String> allowedOrigins = new HashSet<String>();
    U2fPrimitives u2f = new U2fPrimitives();

    @Rule
    public ExpectedException expectedException = ExpectedException.none();

    @Before
    public void setup() throws Exception {
        allowedOrigins.add("http://example.com");
    }

    @Test
    public void finishRegistration() throws Exception {
        RegisterRequest registerRequest = new RegisterRequest(SERVER_CHALLENGE_REGISTER_BASE64, APP_ID_ENROLL);

        DeviceRegistration response = u2f.finishRegistration(registerRequest, new RegisterResponse(TestVectors.REGISTRATION_DATA_BASE64, CLIENT_DATA_REGISTRATION_BASE64), TRUSTED_DOMAINS);
        assertEquals(KEY_HANDLE_BASE64, response.getKeyHandle());
    }

    @Test
    public void finishRegistration2() throws Exception {
        RegisterRequest registerRequest = new RegisterRequest(SERVER_CHALLENGE_REGISTER_BASE64, APP_ID_ENROLL);

        DeviceRegistration deviceRegistration = u2f.finishRegistration(registerRequest, new RegisterResponse(AcmeKey.REGISTRATION_DATA_BASE64, AcmeKey.CLIENT_DATA_BASE64), TRUSTED_DOMAINS);

        assertEquals(new DeviceRegistration(AcmeKey.KEY_HANDLE, AcmeKey.USER_PUBLIC_KEY_B64, AcmeKey.ATTESTATION_CERTIFICATE, 0), deviceRegistration);

    }

    @Test
    public void finishRegistrationWithoutAllowedAppIds() throws Exception {
        RegisterRequest registerRequest = new RegisterRequest(SERVER_CHALLENGE_REGISTER_BASE64, APP_ID_ENROLL);

        DeviceRegistration response = u2f.finishRegistration(
            registerRequest,
            new RegisterResponse(
                TestVectors.REGISTRATION_DATA_BASE64,
                CLIENT_DATA_REGISTRATION_BASE64
            )
        );

        assertEquals(KEY_HANDLE_BASE64, response.getKeyHandle());
    }

    @Test
    public void finishRegistrationShouldDetectIncorrectAppId() throws Exception {
        expectedException.expectCause(isA(U2fBadInputException.class));

        RegisterRequest registerRequest = new RegisterRequest(SERVER_CHALLENGE_REGISTER_BASE64, APP_ID_ENROLL);

        DeviceRegistration response = u2f.finishRegistration(
            registerRequest,
            new RegisterResponse(
                TestVectors.REGISTRATION_DATA_WITH_DIFFERENT_APP_ID_BASE64,
                CLIENT_DATA_REGISTRATION_BASE64
            )
        );

        fail("finishRegistration did not detect incorrect app ID");
    }

    @Test
    public void finishRegistrationShouldDetectIncorrectChallenge() throws Exception {
        expectedException.expectCause(isA(U2fBadInputException.class));

        RegisterRequest registerRequest = new RegisterRequest(SERVER_CHALLENGE_REGISTER_BASE64, APP_ID_ENROLL);

        String clientDataBase64 = U2fB64Encoding.encode("{\"typ\":\"navigator.id.finishEnrollment\",\"challenge\":\"ARGHABLARGHLER\",\"origin\":\"http://example.com\"}".getBytes("UTF-8"));

        u2f.finishRegistration(
            registerRequest,
            new RegisterResponse(
                TestVectors.REGISTRATION_DATA_BASE64,
                clientDataBase64
            )
        );

        fail("finishRegistration did not detect incorrect challenge");
    }

    @Test
    public void finishRegistrationShouldDetectIncorrectClientDataType() throws Exception {
        expectedException.expectCause(isA(U2fBadInputException.class));

        RegisterRequest registerRequest = new RegisterRequest(SERVER_CHALLENGE_REGISTER_BASE64, APP_ID_ENROLL);

        String clientDataBase64 = U2fB64Encoding.encode("{\"typ\":\"navigator.id.launchNukes\",\"challenge\":\"vqrS6WXDe1JUs5_c3i4-LkKIHRr-3XVb3azuA5TifHo\",\"origin\":\"http://example.com\"}".getBytes("UTF-8"));

        u2f.finishRegistration(
            registerRequest,
            new RegisterResponse(
                TestVectors.REGISTRATION_DATA_WITH_DIFFERENT_CLIENT_DATA_TYPE_BASE64,
                clientDataBase64
            )
        );

        fail("finishRegistration did not detect incorrect type in client data");
    }

    @Test
    public void finishRegistrationShouldDetectIncorrectClientDataOrigin() throws Exception {
        expectedException.expectCause(isA(U2fBadInputException.class));

        RegisterRequest registerRequest = new RegisterRequest(SERVER_CHALLENGE_REGISTER_BASE64, APP_ID_ENROLL);

        String clientDataBase64 = U2fB64Encoding.encode("{\"typ\":\"navigator.id.finishEnrollment\",\"challenge\":\"vqrS6WXDe1JUs5_c3i4-LkKIHRr-3XVb3azuA5TifHo\",\"origin\":\"http://evil.com\"}".getBytes("UTF-8"));

        u2f.finishRegistration(
            registerRequest,
            new RegisterResponse(
                TestVectors.REGISTRATION_DATA_BASE64,
                clientDataBase64
            )
        );

        fail("finishRegistration did not detect incorrect origin in client data");
    }

    @Test
    public void finishSignature() throws Exception {
        SignRequest signRequest = SignRequest.builder()
            .challenge(SERVER_CHALLENGE_SIGN_BASE64)
            .appId(APP_ID_SIGN)
            .keyHandle(KEY_HANDLE_BASE64)
            .build();

        SignResponse tokenResponse = new SignResponse(CLIENT_DATA_SIGN_BASE64,
                SIGN_RESPONSE_DATA_BASE64, KEY_HANDLE_BASE64);

        u2f.finishSignature(signRequest, tokenResponse, new DeviceRegistration(KEY_HANDLE_BASE64, USER_PUBLIC_KEY_SIGN_HEX, ATTESTATION_CERTIFICATE, 0), allowedOrigins);
    }


    @Test(expected = U2fAuthenticationException.class)
    public void finishSignature_badOrigin() throws Exception {
        Set<String> allowedOrigins = ImmutableSet.of("some-other-domain.com");
        SignRequest request = SignRequest.builder()
            .challenge(SERVER_CHALLENGE_SIGN_BASE64)
            .appId(APP_ID_SIGN)
            .keyHandle(KEY_HANDLE_BASE64)
            .build();

        SignResponse response = new SignResponse(CLIENT_DATA_SIGN_BASE64,
                SIGN_RESPONSE_DATA_BASE64, SERVER_CHALLENGE_SIGN_BASE64);

        u2f.finishSignature(request, response, new DeviceRegistration(KEY_HANDLE_BASE64, USER_PUBLIC_KEY_SIGN_HEX, ATTESTATION_CERTIFICATE, 0), allowedOrigins);
    }

    @Test(expected = U2fBadInputException.class)
    public void finishAuthentication_badBase64() throws Exception {
        SignRequest authentication = SignRequest.builder()
            .challenge(SERVER_CHALLENGE_SIGN_BASE64)
            .appId(APP_ID_SIGN)
            .keyHandle(KEY_HANDLE_BASE64)
            .build();

        SignResponse response = new SignResponse("****", "****", "****");

        u2f.finishSignature(authentication, response, new DeviceRegistration(KEY_HANDLE_BASE64, USER_PUBLIC_KEY_SIGN_HEX, ATTESTATION_CERTIFICATE, 0));
    }

    @Test(expected = U2fBadInputException.class)
    public void finishAuthentication_clientDataMissingField() throws Exception {
        SignRequest authentication = SignRequest.builder()
            .challenge(SERVER_CHALLENGE_SIGN_BASE64)
            .appId(APP_ID_SIGN)
            .keyHandle(KEY_HANDLE_BASE64)
            .build();

        SignResponse response = new SignResponse(U2fB64Encoding.encode("{}".getBytes()), "", "");

        u2f.finishSignature(authentication, response, new DeviceRegistration(KEY_HANDLE_BASE64, USER_PUBLIC_KEY_SIGN_HEX, ATTESTATION_CERTIFICATE, 0));
    }

    @Test
    public void finishAuthentication_truncatedData() throws Exception {
        expectedException.expectCause(isA(U2fBadInputException.class));
        SignRequest authentication = SignRequest.builder()
            .challenge(SERVER_CHALLENGE_SIGN_BASE64)
            .appId(APP_ID_SIGN)
            .keyHandle(KEY_HANDLE_BASE64)
            .build();

        SignResponse response = new SignResponse(CLIENT_DATA_SIGN_BASE64,
                "", KEY_HANDLE_BASE64);

        u2f.finishSignature(authentication, response, new DeviceRegistration(KEY_HANDLE_BASE64, USER_PUBLIC_KEY_SIGN_HEX, ATTESTATION_CERTIFICATE, 0));
    }

    @Test(expected = IllegalArgumentException.class)
    public void startSignature_compromisedDevice() throws Exception {
        RegisterRequest registerRequest = new RegisterRequest(SERVER_CHALLENGE_REGISTER_BASE64, APP_ID_ENROLL);
        DeviceRegistration deviceRegistration = u2f.finishRegistration(registerRequest, new RegisterResponse(AcmeKey.REGISTRATION_DATA_BASE64, AcmeKey.CLIENT_DATA_BASE64), TRUSTED_DOMAINS);
        deviceRegistration.markCompromised();

        u2f.startSignature(APP_ID_ENROLL, deviceRegistration);
    }

    @Test(expected = IllegalArgumentException.class)
    public void finishSignature_compromisedDevice() throws Exception {
        SignRequest signRequest = SignRequest.builder()
            .challenge(SERVER_CHALLENGE_SIGN_BASE64)
            .appId(APP_ID_SIGN)
            .keyHandle(KEY_HANDLE_BASE64)
            .build();

        SignResponse tokenResponse = new SignResponse(CLIENT_DATA_SIGN_BASE64,
                SIGN_RESPONSE_DATA_BASE64, KEY_HANDLE_BASE64);

        DeviceRegistration deviceRegistration = new DeviceRegistration(KEY_HANDLE_BASE64, USER_PUBLIC_KEY_SIGN_HEX, ATTESTATION_CERTIFICATE, 0);
        deviceRegistration.markCompromised();

        u2f.finishSignature(signRequest, tokenResponse, deviceRegistration, allowedOrigins);
    }

    @Test
    public void finishSignatureShouldDetectInvalidUserPresence() throws Exception {
        expectedException.expectCause(isA(U2fBadInputException.class));

        SignRequest signRequest = SignRequest.builder()
                .challenge(SERVER_CHALLENGE_SIGN_BASE64)
                .appId(APP_ID_SIGN)
                .keyHandle(KEY_HANDLE_BASE64)
                .build();

        SignResponse tokenResponse = new SignResponse(
            CLIENT_DATA_SIGN_BASE64,
            SIGN_RESPONSE_INVALID_USER_PRESENCE_BASE64,
            KEY_HANDLE_BASE64
        );

        u2f.finishSignature(
            signRequest,
            tokenResponse,
            new DeviceRegistration(
                KEY_HANDLE_BASE64,
                USER_PUBLIC_KEY_SIGN_HEX,
                ATTESTATION_CERTIFICATE,
                0
            ),
            allowedOrigins
        );

        fail("finishSignature did not detect a non-0x01 user presence byte in the sign response.");
    }

    @Test(expected = IllegalArgumentException.class)
    public void finishSignatureShouldDetectIncorrectDeviceRegistration() throws Exception {
        SignRequest signRequest = SignRequest.builder()
            .challenge(SERVER_CHALLENGE_SIGN_BASE64)
            .appId(APP_ID_SIGN)
            .keyHandle(KEY_HANDLE_BASE64)
            .build();

        SignResponse tokenResponse = new SignResponse(
            CLIENT_DATA_SIGN_BASE64,
            SIGN_RESPONSE_DATA_BASE64,
            KEY_HANDLE_BASE64
        );

        u2f.finishSignature(
            signRequest,
            tokenResponse,
            new DeviceRegistration(
                "ARGHABLARGHLER",
                USER_PUBLIC_KEY_SIGN_HEX,
                ATTESTATION_CERTIFICATE,
                0
            ),
            allowedOrigins
        );
    }

}
