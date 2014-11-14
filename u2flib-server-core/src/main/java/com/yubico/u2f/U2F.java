/*
 * Copyright 2014 Yubico.
 * Copyright 2014 Google Inc. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */

package com.yubico.u2f;

import com.google.common.base.Objects;
import com.google.common.base.Optional;
import com.google.common.base.Predicate;
import com.google.common.collect.Iterables;
import com.google.common.collect.Lists;
import com.yubico.u2f.crypto.BouncyCastleCrypto;
import com.yubico.u2f.crypto.ChallengeGenerator;
import com.yubico.u2f.crypto.Crypto;
import com.yubico.u2f.crypto.RandomChallengeGenerator;
import com.yubico.u2f.data.DeviceRegistration;
import com.yubico.u2f.data.messages.*;
import com.yubico.u2f.data.messages.key.RawAuthenticateResponse;
import com.yubico.u2f.data.messages.key.RawRegisterResponse;
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding;
import com.yubico.u2f.exceptions.U2fException;

import java.util.List;
import java.util.Set;

public class U2F {

    public static final String AUTHENTICATE_TYP = "navigator.id.getAssertion";
    public static final String REGISTER_TYPE = "navigator.id.finishEnrollment";
    public static final String U2F_VERSION = "U2F_V2";

    private final Crypto crypto;
    private final ChallengeGenerator challengeGenerator;

    public U2F(Crypto crypto, ChallengeGenerator challengeGenerator) {
        this.crypto = crypto;
        this.challengeGenerator = challengeGenerator;
    }

    public U2F() {
        this(new BouncyCastleCrypto(), new RandomChallengeGenerator());
    }

    /**
     * @see U2F#startRegistration(String, byte[])
     */
    public RegisterRequest startRegistration(String appId) {
        return startRegistration(appId, challengeGenerator.generateChallenge());
    }

    /**
     * Initiates the registration of a device.
     *
     * @param appId the U2F AppID. Set this to the Web Origin of the login page, unless you need to
     *              support logging in from multiple Web Origins.
     * @param challenge          the challenge to use
     * @return a RegisterRequest, which should be sent to the client and temporary saved by the
     * server.
     */
    public RegisterRequest startRegistration(String appId, byte[] challenge) {
        return new RegisterRequest(U2fB64Encoding.encode(challenge), appId);
    }

    /**
     * Initiates a high-level registration of a device, given a set of already registered devices.
     * @param appId the U2F AppID. Set this to the Web Origin of the login page, unless you need to
     *              support logging in from multiple Web Origins.
     * @param devices the devices currently registered to the user.
     * @return a RegisterRequestData, which should be sent to the client and temporarily saved by the server.
     */
    public RegisterRequestData startRegistration(String appId, Iterable<? extends DeviceRegistration> devices) {
        List<AuthenticateRequest> authenticateRequests = Lists.newArrayList();
        for(DeviceRegistration device : devices) {
            authenticateRequests.add(startAuthentication(appId, device));
        }

        RegisterRequest registerRequest = startRegistration(appId);
        return new RegisterRequestData(appId, devices, this, challengeGenerator);
    }

    /***
     * @see U2F#finishRegistration(com.yubico.u2f.data.messages.RegisterRequestData, com.yubico.u2f.data.messages.RegisterResponse, java.util.Set)
     */
    public DeviceRegistration finishRegistration(RegisterRequestData registerRequestData, RegisterResponse response) throws U2fException {
        return finishRegistration(registerRequestData, response, null);
    }

    /**
     * Finishes a previously started high-level registration.
     * @param registerRequestData the RegisterResponseData created by calling startRegistration
     * @param response The response from the device/client.
     * @param facets A list of valid facets to verify against.
     * @return a DeviceRegistration object, holding information about the registered device. Servers should
     * persist this.
     * @throws U2fException
     */
    public DeviceRegistration finishRegistration(RegisterRequestData registerRequestData, RegisterResponse response, Set<String> facets) throws U2fException {
        return finishRegistration(registerRequestData.getRegisterRequest(response), response, facets);
    }

    /**
     * @see U2F#finishRegistration(com.yubico.u2f.data.messages.RegisterRequest, com.yubico.u2f.data.messages.RegisterResponse, java.util.Set)
     */
    public DeviceRegistration finishRegistration(RegisterRequest registerRequest, RegisterResponse response) throws U2fException {
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
                                                 Set<String> facets) throws U2fException {
        ClientData clientData = response.getClientData();
        clientData.checkContent(REGISTER_TYPE, registerRequest.getChallenge(), Optional.fromNullable(facets));

        RawRegisterResponse rawRegisterResponse = RawRegisterResponse.fromBase64(response.getRegistrationData(), crypto);
        rawRegisterResponse.checkSignature(registerRequest.getAppId(), clientData.asJson());
        return rawRegisterResponse.createDevice();
    }

    public AuthenticateRequestData startAuthentication(String appId, Iterable<? extends DeviceRegistration> devices) {
        return new AuthenticateRequestData(appId, devices, this, challengeGenerator);
    }

    /**
     * Initiates the authentication process.
     *
     * @see U2F#startAuthentication(String, com.yubico.u2f.data.DeviceRegistration, byte[])
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
        return new AuthenticateRequest(
                U2fB64Encoding.encode(challenge),
                appId,
                deviceRegistration.getKeyHandle()
        );
    }

    /**
     * @see U2F#finishAuthentication(com.yubico.u2f.data.messages.AuthenticateRequestData, com.yubico.u2f.data.messages.AuthenticateResponse, Iterable, java.util.Set)
     */
    public DeviceRegistration finishAuthentication(AuthenticateRequestData authenticateRequestData, AuthenticateResponse response, Iterable<? extends DeviceRegistration> devices) throws U2fException {
        return finishAuthentication(authenticateRequestData, response, devices, null);
    }

    /**
     * Finishes a previously started high-level authentication.
     * @param authenticateRequestData the AuthenticateRequestData created by calling startAuthentication
     * @param response                the response from the device/client.
     * @param devices                 the devices currently registered to the user.
     * @param facets                  A list of valid facets to verify against.
     * @return                        The (updated) DeviceRegistration that was authenticated against.
     * @throws U2fException
     */
    public DeviceRegistration finishAuthentication(AuthenticateRequestData authenticateRequestData, AuthenticateResponse response, Iterable<? extends DeviceRegistration> devices, Set<String> facets) throws U2fException {
        final AuthenticateRequest request = authenticateRequestData.getAuthenticateRequest(response);
        DeviceRegistration device = Iterables.find(devices, new Predicate<DeviceRegistration>() {
            @Override
            public boolean apply(DeviceRegistration input) {
                return Objects.equal(request.getKeyHandle(), input.getKeyHandle());
            }
        });

        finishAuthentication(request, response, device, facets);
        return device;
    }

    /**
     * @see U2F#finishAuthentication(com.yubico.u2f.data.messages.AuthenticateRequest, com.yubico.u2f.data.messages.AuthenticateResponse, com.yubico.u2f.data.DeviceRegistration, java.util.Set)
     */
    public void finishAuthentication(AuthenticateRequest authenticateRequest,
                                     AuthenticateResponse response,
                                     DeviceRegistration deviceRegistration) throws U2fException {
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
                                     Set<String> facets) throws U2fException {
        ClientData clientData = response.getClientData();
        clientData.checkContent(AUTHENTICATE_TYP, authenticateRequest.getChallenge(), Optional.fromNullable(facets));

        RawAuthenticateResponse rawAuthenticateResponse = RawAuthenticateResponse.fromBase64(
                response.getSignatureData(), crypto
        );
        rawAuthenticateResponse.checkSignature(
                authenticateRequest.getAppId(),
                clientData.asJson(),
                deviceRegistration.getPublicKey()
        );
        rawAuthenticateResponse.checkUserPresence();
        deviceRegistration.checkAndUpdateCounter(rawAuthenticateResponse.getCounter());
    }
}
