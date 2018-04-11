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
import com.yubico.u2f.data.messages.key.RawSignResponse;
import com.yubico.u2f.data.messages.key.RawRegisterResponse;
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding;
import com.yubico.u2f.exceptions.DeviceCompromisedException;
import com.yubico.u2f.exceptions.InvalidDeviceCounterException;
import com.yubico.u2f.exceptions.U2fBadInputException;

import com.yubico.u2f.exceptions.U2fAuthenticationException;
import com.yubico.u2f.exceptions.U2fRegistrationException;
import java.util.Set;

import static com.google.common.base.Preconditions.checkArgument;

public class U2fPrimitives {

    private static final String SIGN_TYPE = "navigator.id.getAssertion";
    private static final String REGISTER_TYPE = "navigator.id.finishEnrollment";
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
    public DeviceRegistration finishRegistration(RegisterRequest registerRequest, RegisterResponse response) throws U2fRegistrationException {
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
                                                 Set<String> facets) throws U2fRegistrationException {
        try {
            ClientData clientData = response.getClientData();
            clientData.checkContent(REGISTER_TYPE, registerRequest.getChallenge(), Optional.fromNullable(facets));

            RawRegisterResponse rawRegisterResponse = RawRegisterResponse.fromBase64(response.getRegistrationData(), crypto);
            rawRegisterResponse.checkSignature(registerRequest.getAppId(), clientData.asJson());
            return rawRegisterResponse.createDevice();
        } catch (U2fBadInputException e) {
            throw new U2fRegistrationException("finishRegistration failed", e);
        }
    }

    /**
     * Initiates the signing process.
     *
     * @see U2fPrimitives#startSignature(String, com.yubico.u2f.data.DeviceRegistration, byte[])
     */
    public SignRequest startSignature(String appId, DeviceRegistration deviceRegistration) {
        return startSignature(appId, deviceRegistration, challengeGenerator.generateChallenge());
    }

    /**
     * Initiates the signing process.
     *
     * @param appId              the U2F AppID. Set this to the Web Origin of the login page, unless you need to
     *                           support logging in from multiple Web Origins.
     * @param deviceRegistration the DeviceRegistration for which to initiate signing.
     * @param challenge          the challenge to use
     * @return an SignRequest which should be sent to the client and temporary saved by
     * the server.
     */
    public SignRequest startSignature(String appId, DeviceRegistration deviceRegistration, byte[] challenge) {
        checkArgument(!deviceRegistration.isCompromised(), "Device has been marked as compromised, cannot sign.");

        return SignRequest.builder()
            .appId(appId)
            .challenge(U2fB64Encoding.encode(challenge))
            .keyHandle(deviceRegistration.getKeyHandle())
            .build();
    }

    /**
     * @see U2fPrimitives#finishSignature(SignRequest, SignResponse, com.yubico.u2f.data.DeviceRegistration, java.util.Set)
     */
    public void finishSignature(SignRequest signRequest,
                                SignResponse response,
                                DeviceRegistration deviceRegistration) throws U2fAuthenticationException {
        finishSignature(signRequest, response, deviceRegistration, null);
    }

    /**
     * Finishes a previously started signature.
     *
     * @param signRequest
     * @param response            the response from the device/client.
     */
    public void finishSignature(SignRequest signRequest,
                                SignResponse response,
                                DeviceRegistration deviceRegistration,
                                Set<String> facets) throws U2fAuthenticationException {
        checkArgument(!deviceRegistration.isCompromised(), "Device has been marked as compromised, cannot sign.");
        checkArgument(signRequest.getKeyHandle().equals(deviceRegistration.getKeyHandle()), "Wrong DeviceRegistration for the given SignRequest");
        if (!deviceRegistration.getKeyHandle().equals(response.getKeyHandle())) {
            throw new U2fAuthenticationException("KeyHandle of SignResponse does not match");
        }

        try {
            ClientData clientData = response.getClientData();
            clientData.checkContent(SIGN_TYPE, signRequest.getChallenge(), Optional.fromNullable(facets));

            RawSignResponse rawSignResponse = RawSignResponse.fromBase64(
                response.getSignatureData(), crypto
            );
            rawSignResponse.checkSignature(
                signRequest.getAppId(),
                clientData.asJson(),
                U2fB64Encoding.decode(deviceRegistration.getPublicKey())
            );
            rawSignResponse.checkUserPresence();
            deviceRegistration.checkAndUpdateCounter(rawSignResponse.getCounter());
        } catch (U2fBadInputException e) {
            throw new U2fAuthenticationException("finishSignature failed", e);
        }
    }
}
