/*
 * Copyright 2014 Yubico.
 * Copyright 2014 Google Inc. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */

package com.yubico.u2f;

import com.google.common.base.Optional;
import com.yubico.u2f.crypto.BouncyCastleCrypto;
import com.yubico.u2f.crypto.ChallengeGenerator;
import com.yubico.u2f.crypto.Crypto;
import com.yubico.u2f.crypto.RandomChallengeGenerator;
import com.yubico.u2f.data.DeviceRegistration;
import com.yubico.u2f.data.messages.*;
import com.yubico.u2f.data.messages.key.RawAuthenticateResponse;
import com.yubico.u2f.data.messages.key.RawRegisterResponse;
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding;
import com.yubico.u2f.exceptions.DeviceCompromisedException;
import com.yubico.u2f.exceptions.U2fBadInputException;

import java.util.Set;

import static com.google.common.base.Preconditions.checkArgument;

public class U2fPrimitives {

    public static final String AUTHENTICATE_TYP = "navigator.id.getAssertion";
    public static final String REGISTER_TYPE = "navigator.id.finishEnrollment";
    public static final String U2F_VERSION = "U2F_V2";

    private final Crypto crypto;
    private final ChallengeGenerator challengeGenerator;

    public U2fPrimitives(Crypto crypto, ChallengeGenerator challengeGenerator) {
        this.crypto = crypto;
        this.challengeGenerator = challengeGenerator;
    }

    public U2fPrimitives() {
        this(new BouncyCastleCrypto(), new RandomChallengeGenerator());
    }

    /**
     * @see U2fPrimitives#startRegistration(String, byte[])
     */
    public RegisterRequest startRegistration(String appId) {
        return startRegistration(appId, challengeGenerator.generateChallenge());
    }

    /**
     * Initiates the registration of a device.
     *
     * @param appId     the U2F AppID. Set this to the Web Origin of the login page, unless you need to
     *                  support logging in from multiple Web Origins.
     * @param challenge the challenge to use
     * @return a RegisterRequest, which should be sent to the client and temporary saved by the
     * server.
     */
    public RegisterRequest startRegistration(String appId, byte[] challenge) {
        return new RegisterRequest(U2fB64Encoding.encode(challenge), appId);
    }

    /**
     * @see U2fPrimitives#finishRegistration(com.yubico.u2f.data.messages.RegisterRequest, com.yubico.u2f.data.messages.RegisterResponse, java.util.Set)
     */
    public DeviceRegistration finishRegistration(RegisterRequest registerRequest, RegisterResponse response) throws U2fBadInputException {
        return finishRegistration(registerRequest, response, null);
    }

    /**
     * Finishes a previously started registration.
     *
     * @param registerRequest
     * @param response        the response from the device/client.
     * @return a DeviceRegistration object, holding information about the registered device. Servers should
     * persist this.
     */
    public DeviceRegistration finishRegistration(RegisterRequest registerRequest,
                                                 RegisterResponse response,
                                                 Set<String> facets) throws U2fBadInputException {
        ClientData clientData = response.getClientData();
        clientData.checkContent(REGISTER_TYPE, registerRequest.getChallenge(), Optional.fromNullable(facets));

        RawRegisterResponse rawRegisterResponse = RawRegisterResponse.fromBase64(response.getRegistrationData(), crypto);
        rawRegisterResponse.checkSignature(registerRequest.getAppId(), clientData.asJson());
        return rawRegisterResponse.createDevice();
    }

    /**
     * Initiates the authentication process.
     *
     * @see U2fPrimitives#startAuthentication(String, com.yubico.u2f.data.DeviceRegistration, byte[])
     */
    public AuthenticateRequest startAuthentication(String appId, DeviceRegistration deviceRegistration) {
        return startAuthentication(appId, deviceRegistration, challengeGenerator.generateChallenge());
    }

    /**
     * Initiates the authentication process.
     *
     * @param appId              the U2F AppID. Set this to the Web Origin of the login page, unless you need to
     *                           support logging in from multiple Web Origins.
     * @param deviceRegistration the DeviceRegistration for which to initiate authentication.
     * @param challenge          the challenge to use
     * @return an AuthenticateRequest which should be sent to the client and temporary saved by
     * the server.
     */
    public AuthenticateRequest startAuthentication(String appId, DeviceRegistration deviceRegistration, byte[] challenge) {
        checkArgument(!deviceRegistration.isCompromised(), "Device has been marked as compromised, cannot authenticate");

        return new AuthenticateRequest(
                U2fB64Encoding.encode(challenge),
                appId,
                deviceRegistration.getKeyHandle()
        );
    }

    /**
     * @see U2fPrimitives#finishAuthentication(com.yubico.u2f.data.messages.AuthenticateRequest, com.yubico.u2f.data.messages.AuthenticateResponse, com.yubico.u2f.data.DeviceRegistration, java.util.Set)
     */
    public void finishAuthentication(AuthenticateRequest authenticateRequest,
                                     AuthenticateResponse response,
                                     DeviceRegistration deviceRegistration) throws U2fBadInputException, DeviceCompromisedException {
        finishAuthentication(authenticateRequest, response, deviceRegistration, null);
    }

    /**
     * Finishes a previously started authentication.
     *
     * @param authenticateRequest
     * @param response            the response from the device/client.
     */
    public void finishAuthentication(AuthenticateRequest authenticateRequest,
                                     AuthenticateResponse response,
                                     DeviceRegistration deviceRegistration,
                                     Set<String> facets) throws U2fBadInputException, DeviceCompromisedException {
        checkArgument(!deviceRegistration.isCompromised(), "Device has been marked as compromised, cannot authenticate");
        checkArgument(authenticateRequest.getKeyHandle().equals(deviceRegistration.getKeyHandle()), "Wrong DeviceRegistration for the given AuthenticateRequest");
        if (!deviceRegistration.getKeyHandle().equals(response.getKeyHandle())) {
            throw new U2fBadInputException("KeyHandle of AuthenticateResponse does not match");
        }

        ClientData clientData = response.getClientData();
        clientData.checkContent(AUTHENTICATE_TYP, authenticateRequest.getChallenge(), Optional.fromNullable(facets));

        RawAuthenticateResponse rawAuthenticateResponse = RawAuthenticateResponse.fromBase64(
                response.getSignatureData(), crypto
        );
        rawAuthenticateResponse.checkSignature(
                authenticateRequest.getAppId(),
                clientData.asJson(),
                U2fB64Encoding.decode(deviceRegistration.getPublicKey())
        );
        rawAuthenticateResponse.checkUserPresence();
        deviceRegistration.checkAndUpdateCounter(rawAuthenticateResponse.getCounter());
    }
}
