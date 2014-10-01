/*
 * Copyright 2014 Yubico.
 * Copyright 2014 Google Inc. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */

package com.yubico.u2f.server.impl;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;

import com.yubico.u2f.U2fException;
import com.yubico.u2f.codec.RawMessageCodec;
import com.yubico.u2f.key.UserPresenceVerifier;
import com.yubico.u2f.server.Crypto;
import com.yubico.u2f.server.U2fServer;
import com.yubico.u2f.server.data.Device;
import com.yubico.u2f.server.data.SignSessionData;
import org.apache.commons.codec.binary.Base64;

import com.google.common.collect.ImmutableList;
import com.google.common.collect.ImmutableSet;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.yubico.u2f.key.messages.AuthenticateResponse;
import com.yubico.u2f.key.messages.RegisterResponse;
import com.yubico.u2f.server.ChallengeGenerator;
import com.yubico.u2f.server.data.EnrollSessionData;
import com.yubico.u2f.server.messages.TokenChallenge;
import com.yubico.u2f.server.messages.TokenResponse;
import com.yubico.u2f.server.messages.AuthenticationRequest;
import com.yubico.u2f.server.messages.SignResponse;

public class U2fServerImpl implements U2fServer {

  private static final String U2F_VERSION = "U2F_V2";
  private static final String TYPE_PARAM = "typ";
  private static final String CHALLENGE_PARAM = "challenge";
  private static final String ORIGIN_PARAM = "origin";

  // TODO: use these for channel id checks in checkClientData
  @SuppressWarnings("unused")
  private static final String CHANNEL_ID_PARAM = "cid_pubkey";
  @SuppressWarnings("unused")
  private static final String UNUSED_CHANNEL_ID = "";
  
  private static final Logger Log = Logger.getLogger(U2fServerImpl.class.getName());
  public static final int INITIAL_COUNTER_VALUE = 0;

  private final ChallengeGenerator challengeGenerator;
  private final Crypto crypto;
  private final Set<String> allowedOrigins;
  private Set<X509Certificate> trustedAttestationCertificates = new HashSet<X509Certificate>(); //TODO: instantiate from constructor param
  private String appId;

  public U2fServerImpl(Set<String> origins, String appId) {
    this(new BouncyCastleCrypto(), origins, appId);
  }

  public U2fServerImpl(Crypto crypto, Set<String> origins, String appId) {
    this.challengeGenerator = new ChallengeGeneratorImpl();
    this.crypto = crypto;
    this.allowedOrigins = canonicalizeOrigins(origins);
    this.appId = appId;
  }

  @Override
  public TokenChallenge startRegistration() throws IOException {

    byte[] challenge = challengeGenerator.generateChallenge();
    String challengeBase64 = Base64.encodeBase64URLSafeString(challenge);
    return new TokenChallenge(U2F_VERSION, challengeBase64, appId);
  }

  @Override
  public Device finishRegistration(TokenChallenge challenge, TokenResponse tokenResponse)
          throws U2fException, IOException {

    RegisterResponse registerResponse = RawMessageCodec
            .decodeRegisterResponse(tokenResponse.getRegistrationData());
    X509Certificate attestationCertificate = registerResponse.getAttestationCertificate();
    checkIsTrusted(attestationCertificate);

    byte[] clientData = checkClientData(tokenResponse.getClientData(), "navigator.id.finishEnrollment", challenge);
    byte[] userPublicKey = registerResponse.getUserPublicKey();
    byte[] keyHandle = registerResponse.getKeyHandle();
    byte[] signedBytes = RawMessageCodec.encodeRegistrationSignedBytes(
            crypto.hash(challenge.getAppId()),
            crypto.hash(clientData),
            keyHandle,
            userPublicKey
    );
    crypto.checkSignature(attestationCertificate, signedBytes, registerResponse.getSignature());

    // The first time we create the SecurityKeyData, we set the counter value to 0.
    // We don't actually know what the counter value of the real device is - but it will
    // be something bigger (or equal) to 0, so subsequent signatures will check out ok.
    Device device = new Device(
            keyHandle,
            userPublicKey,
            attestationCertificate,
            INITIAL_COUNTER_VALUE
    );
    return device;
  }

  private void checkIsTrusted(X509Certificate attestationCertificate) throws IOException {
    if (!trustedAttestationCertificates.contains(attestationCertificate)) {
      Log.warning("Attestation cert is not trusted"); // TODO: Should this be more than a warning?
    }
  }

  @Override
  public List<AuthenticationRequest> startAuthentication(String appId, Device device) throws U2fException, IOException {

    ImmutableList.Builder<AuthenticationRequest> result = ImmutableList.builder();

    byte[] challenge = challengeGenerator.generateChallenge();

    AuthenticationRequest authenticationRequest = new AuthenticationRequest(
          U2F_VERSION,
          Base64.encodeBase64URLSafeString(challenge),
          appId,
          Base64.encodeBase64URLSafeString(device.getKeyHandle())
    );
    result.add(authenticationRequest);
    return result.build();
  }

  public long finishAuthentication(SignResponse signResponse, TokenChallenge sessionData, Device device) throws U2fException, IOException {

    byte[] clientData = checkClientData(signResponse.getBd(), "navigator.id.getAssertion", sessionData);

    AuthenticateResponse authenticateResponse = RawMessageCodec.decodeAuthenticateResponse(signResponse.getSign());
    byte userPresence = authenticateResponse.getUserPresence();
    if (userPresence != UserPresenceVerifier.USER_PRESENT_FLAG) {
      throw new U2fException("User presence invalid during authentication");
    }

    int counter = authenticateResponse.getCounter();
    if (counter <= device.getCounter()) {
      throw new U2fException("Counter value smaller than expected!");
    }
    
    byte[] signedBytes = RawMessageCodec.encodeAuthenticateSignedBytes(
            crypto.hash(sessionData.getAppId()),
            userPresence,
            counter,
            crypto.hash(clientData)
    );
    crypto.checkSignature(
            crypto.decodePublicKey(device.getPublicKey()),
            signedBytes,
            authenticateResponse.getSignature()
    );

    return counter + 1;
  }

  private byte[] checkClientData(String clientDataBase64, String messageType, TokenChallenge challenge)
          throws U2fException {

    byte[] clientDataBytes = Base64.decodeBase64(clientDataBase64);
    JsonElement clientDataAsElement = new JsonParser().parse(new String(clientDataBytes));
    if (!clientDataAsElement.isJsonObject()) {
      throw new U2fException("clientData has wrong format");
    }
    
    JsonObject clientData = clientDataAsElement.getAsJsonObject();
    
    // check that the right "typ" parameter is present in the clientData JSON
    if (!clientData.has(TYPE_PARAM)) {
      throw new U2fException("Bad clientData: missing 'typ' param");
    }

    String type = clientData.get(TYPE_PARAM).getAsString();
    if (!messageType.equals(type)) {
      throw new U2fException("Bad clientData: bad type " + type);
    }

    // check that the right challenge is in the clientData
    if (!clientData.has(CHALLENGE_PARAM)) {
      throw new U2fException("Bad clientData: missing 'challenge' param");
    }

    if (clientData.has(ORIGIN_PARAM)) {
      verifyOrigin(clientData.get(ORIGIN_PARAM).getAsString());
    }

    String challengeFromClientData = clientData.get(CHALLENGE_PARAM).getAsString();
    if (!challengeFromClientData.equals(challenge.getChallenge())) {
      throw new U2fException("Wrong challenge signed in clientData");
    }

    // TODO: Deal with ChannelID

    return clientDataBytes;
  }

  private String getChallenge(String clientDataBase64) {

    byte[] clientDataBytes = Base64.decodeBase64(clientDataBase64);
    JsonElement clientDataAsElement = new JsonParser().parse(new String(clientDataBytes));
    JsonObject clientData = clientDataAsElement.getAsJsonObject();
    return new String(Base64.decodeBase64(clientData.get(CHALLENGE_PARAM).getAsString()));
  }
  
  private void verifyOrigin(String origin) throws U2fException {
    if (!allowedOrigins.contains(canonicalizeOrigin(origin))) {
      throw new U2fException(origin +
          " is not a recognized home origin for this backend");
    }
  }

  private static Set<String> canonicalizeOrigins(Set<String> origins) {
    ImmutableSet.Builder<String> result = ImmutableSet.builder();
    for (String origin : origins) {
      result.add(canonicalizeOrigin(origin));
    }
    return result.build();
  }

  static String canonicalizeOrigin(String url) {
    try {
      URI uri = new URI(url);
      return uri.getScheme() + "://" + uri.getAuthority();
    } catch (URISyntaxException e) {
      throw new AssertionError("specified bad origin", e);
    }
  }
}
