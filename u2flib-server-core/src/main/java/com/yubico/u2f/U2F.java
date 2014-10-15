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
import com.yubico.u2f.data.messages.*;
import com.yubico.u2f.data.messages.key.RawAuthenticateResponse;
import com.yubico.u2f.data.messages.key.RawRegisterResponse;
import com.yubico.u2f.data.Device;
import com.yubico.u2f.crypto.ChallengeGenerator;
import com.yubico.u2f.crypto.Crypto;
import com.yubico.u2f.crypto.BouncyCastleCrypto;
import com.yubico.u2f.crypto.RandomChallengeGenerator;
import org.apache.commons.codec.binary.Base64;

import java.util.Set;

public class U2F {

  private static final String U2F_VERSION = "U2F_V2";
  private static final ChallengeGenerator challengeGenerator = new RandomChallengeGenerator();
  public static final Crypto crypto = new BouncyCastleCrypto();
  public static final String AUTHENTICATE_TYP = "navigator.id.getAssertion";
  public static final String REGISTER_TYPE = "navigator.id.finishEnrollment";

  /**
   * Initiates the registration of a device.
   *
   * @param appId the U2F AppID. Set this to the Web Origin of the login page, unless you need to
   * support logging in from multiple Web Origins.
   * @return a StartedRegistration, which should be sent to the client and temporary saved by the
   * server.
   */
  public static StartedRegistration startRegistration(String appId) {
    byte[] challenge = challengeGenerator.generateChallenge();
    String challengeBase64 = Base64.encodeBase64URLSafeString(challenge);
    return new StartedRegistration(U2F_VERSION, challengeBase64, appId);
  }

  /**
   * Finishes a previously started registration.
   *
   * @param startedRegistration
   * @param tokenResponse the response from the token/client.
   * @return a Device object, holding information about the registered device. Servers should
   * persist this.
   */
  public static Device finishRegistration(StartedRegistration startedRegistration, RegisterResponse tokenResponse) throws U2fException {
    return finishRegistration(startedRegistration, tokenResponse, null);
  }

  public static Device finishRegistration(StartedRegistration startedRegistration, RegisterResponse tokenResponse, Set<String> facets) throws U2fException {
    ClientData clientData = tokenResponse.getClientData();
    clientData.checkContent(REGISTER_TYPE, startedRegistration.getChallenge(), Optional.fromNullable(facets));

    RawRegisterResponse rawRegisterResponse = RawRegisterResponse.fromBase64(tokenResponse.getRegistrationData());
    rawRegisterResponse.checkSignature(startedRegistration.getAppId(), clientData.getRawClientData());
    return rawRegisterResponse.createDevice();
  }

  /**
   * Initiates the authentication process.
   *
   * @param appId the U2F AppID. Set this to the Web Origin of the login page, unless you need to
   * support logging in from multiple Web Origins.
   * @param device a previously registered Device, for which to initiate authentication.
   * @return a StartedAuthentication which should be sent to the client and temporary saved by
   * the server.
   */
  public static StartedAuthentication startAuthentication(String appId, Device device) {
    byte[] challenge = challengeGenerator.generateChallenge();
    return new StartedAuthentication(
            U2F_VERSION,
            Base64.encodeBase64URLSafeString(challenge),
            appId,
            Base64.encodeBase64URLSafeString(device.getKeyHandle())
    );
  }

  /**
   * Finishes a previously started authentication.
   *
   * @param startedAuthentication
   * @param response the response from the token/client.
   * @return the new value of the Device's counter.
   */
  public static int finishAuthentication(StartedAuthentication startedAuthentication, AuthenticateResponse response, Device device) throws U2fException {
    return finishAuthentication(startedAuthentication, response, device, null);
  }

  public static int finishAuthentication(StartedAuthentication startedAuthentication, AuthenticateResponse response, Device device, Set<String> facets) throws U2fException {
    ClientData clientData = response.getClientData();
    clientData.checkContent(AUTHENTICATE_TYP, startedAuthentication.getChallenge(), Optional.fromNullable(facets));


    RawAuthenticateResponse rawAuthenticateResponse = RawAuthenticateResponse.fromBase64(response.getSignatureData());
    rawAuthenticateResponse.checkSignature(
            startedAuthentication.getAppId(),
            clientData.getRawClientData(),
            device.getPublicKey()
    );
    rawAuthenticateResponse.checkUserPresence();
    return device.checkAndIncrementCounter(rawAuthenticateResponse.getCounter());
  }
}
