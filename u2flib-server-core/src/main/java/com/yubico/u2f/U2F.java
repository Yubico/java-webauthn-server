/* Copyright 2014 Yubico */

package com.yubico.u2f;

import com.google.common.base.Objects;
import com.google.common.base.Predicate;
import com.google.common.collect.Iterables;
import com.yubico.u2f.crypto.BouncyCastleCrypto;
import com.yubico.u2f.crypto.ChallengeGenerator;
import com.yubico.u2f.crypto.RandomChallengeGenerator;
import com.yubico.u2f.data.DeviceRegistration;
import com.yubico.u2f.data.messages.*;
import com.yubico.u2f.exceptions.DeviceCompromisedException;
import com.yubico.u2f.exceptions.InvalidDeviceCounterException;
import com.yubico.u2f.exceptions.NoEligibleDevicesException;
import com.yubico.u2f.exceptions.U2fAuthenticationException;
import com.yubico.u2f.exceptions.U2fBadConfigurationException;
import com.yubico.u2f.exceptions.U2fBadInputException;

import com.yubico.u2f.exceptions.U2fRegistrationException;
import java.util.Set;

public class U2F {

    private final ChallengeGenerator challengeGenerator;
    private final U2fPrimitives primitives;
    private final boolean validateAppId;



    public U2F() {
        this(true);
    }

    public static U2F withoutAppIdValidation() {
        return new U2F(false);
    }

    private U2F(boolean validateAppId) {
        this.challengeGenerator = new RandomChallengeGenerator();
        primitives = new U2fPrimitives(new BouncyCastleCrypto(), challengeGenerator);
        this.validateAppId = validateAppId;
    }

    /**
     * Initiates a high-level registration of a device, given a set of already registered devices.
     *
     * @param appId   the U2F AppID. Set this to the Web Origin of the login page, unless you need to
     *                support logging in from multiple Web Origins.
     * @param devices the devices currently registered to the user.
     * @return a RegisterRequestData, which should be sent to the client and temporarily saved by the server.
     */
    public RegisterRequestData startRegistration(String appId, Iterable<? extends DeviceRegistration> devices) throws U2fBadConfigurationException {
        if(validateAppId) {
            AppId.checkIsValid(appId);
        }
        return new RegisterRequestData(appId, devices, primitives, challengeGenerator);
    }

    public SignRequestData startSignature(String appId, Iterable<? extends DeviceRegistration> devices) throws U2fBadConfigurationException, NoEligibleDevicesException {
        if(validateAppId) {
            AppId.checkIsValid(appId);
        }
        return new SignRequestData(appId, devices, primitives, challengeGenerator);
    }

    /***
     *
     */
    public DeviceRegistration finishRegistration(RegisterRequestData registerRequestData, RegisterResponse response) throws U2fRegistrationException {
        return finishRegistration(registerRequestData, response, null);
    }

    /**
     * Finishes a previously started high-level registration.
     *
     * @param registerRequestData the RegisterResponseData created by calling startRegistration
     * @param response            The response from the device/client.
     * @param facets              A list of valid facets to verify against.
     * @return a DeviceRegistration object, holding information about the registered device. Servers should
     * persist this.
     * @throws U2fRegistrationException if parsing or verification of the response fails
     */
    public DeviceRegistration finishRegistration(RegisterRequestData registerRequestData, RegisterResponse response, Set<String> facets) throws U2fRegistrationException {
        return primitives.finishRegistration(registerRequestData.getRegisterRequest(response), response, facets);
    }

    /**
     * @see U2F#finishSignature(SignRequestData, SignResponse, Iterable, java.util.Set)
     */
    public DeviceRegistration finishSignature(SignRequestData signRequestData, SignResponse response, Iterable<? extends DeviceRegistration> devices) throws U2fAuthenticationException {
        return finishSignature(signRequestData, response, devices, null);
    }

    /**
     * Finishes a previously started high-level signing action.
     *
     * @param signRequestData the SignRequestData created by calling startSignature
     * @param response                the response from the device/client.
     * @param devices                 the devices currently registered to the user.
     * @param facets                  A list of valid facets to verify against.
     * @return The (updated) DeviceRegistration that signed the challenge.
     *
     * @throws InvalidDeviceCounterException if the response is valid but the signature counter has not increased.
     * @throws DeviceCompromisedException if the device with the response's key handle is marked as compromised.
     * @throws U2fAuthenticationException if parsing or verification of the response fails.
     */
    public DeviceRegistration finishSignature(SignRequestData signRequestData, SignResponse response, Iterable<? extends DeviceRegistration> devices, Set<String> facets) throws U2fAuthenticationException {
        try {
            final SignRequest request = signRequestData.getSignRequest(response);
            DeviceRegistration device = Iterables.find(devices, new Predicate<DeviceRegistration>() {
                @Override
                public boolean apply(DeviceRegistration input) {
                    return Objects.equal(request.getKeyHandle(), input.getKeyHandle());
                }
            });

            if (device.isCompromised()) {
                throw new DeviceCompromisedException(device, "The device is marked as possibly compromised, and cannot make trusted signatures.");
            }

            primitives.finishSignature(request, response, device, facets);
            return device;
        } catch (U2fBadInputException e) {
            throw new U2fAuthenticationException("finishSignature failed", e);
        }
    }
}
