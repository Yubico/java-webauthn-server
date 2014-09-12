/*
 * Copyright 2014 Google Inc. All rights reserved.
 * Copyright 2014 Yubico.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */

package com.yubico.u2f.server.impl;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.logging.Logger;

import com.yubico.u2f.U2fException;
import com.yubico.u2f.codec.RawMessageCodec;
import com.yubico.u2f.key.UserPresenceVerifier;
import com.yubico.u2f.server.Crypto;
import com.yubico.u2f.server.U2FServer;
import com.yubico.u2f.server.data.SecurityKeyData;
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
import com.yubico.u2f.server.DataStore;
import com.yubico.u2f.server.data.EnrollSessionData;
import com.yubico.u2f.server.messages.RegistrationRequest;
import com.yubico.u2f.server.messages.RegistrationResponse;
import com.yubico.u2f.server.messages.SignRequest;
import com.yubico.u2f.server.messages.SignResponse;

public class U2FServerReferenceImpl implements U2FServer {

  private static final String U2F_VERSION = "U2F_V2";
  private static final String TYPE_PARAM = "typ";
  private static final String CHALLENGE_PARAM = "challenge";
  private static final String ORIGIN_PARAM = "origin";

  // TODO: use these for channel id checks in checkClientData
  @SuppressWarnings("unused")
  private static final String CHANNEL_ID_PARAM = "cid_pubkey";
  @SuppressWarnings("unused")
  private static final String UNUSED_CHANNEL_ID = "";
  
  private static final Logger Log = Logger.getLogger(U2FServerReferenceImpl.class.getName());
  public static final int INITIAL_COUNTER_VALUE = 0;

  private final ChallengeGenerator challengeGenerator;
  private final DataStore dataStore;
  private final Crypto crypto;
  private final Set<String> allowedOrigins;

  public U2FServerReferenceImpl(ChallengeGenerator challengeGenerator,
      DataStore dataStore, Crypto crypto, Set<String> origins) {
    this.challengeGenerator = challengeGenerator;
    this.dataStore = dataStore;
    this.crypto = crypto;
    this.allowedOrigins = canonicalizeOrigins(origins);
  }

  @Override
  public RegistrationRequest getRegistrationRequest(String accountName, String appId) {

    byte[] challenge = challengeGenerator.generateChallenge(accountName);
    String challengeBase64 = Base64.encodeBase64URLSafeString(challenge);
    String sessionId = dataStore.storeSessionData(
            new EnrollSessionData(accountName, appId, challenge)
    );

    return new RegistrationRequest(U2F_VERSION, challengeBase64, appId, sessionId);
  }

  @Override
  public SecurityKeyData processRegistrationResponse(RegistrationResponse registrationResponse,
          long currentTimeInMillis) throws U2fException {

    EnrollSessionData sessionData = dataStore.getEnrollSessionData(registrationResponse.getSessionId());
    if (sessionData == null) {
      throw new U2fException("Unknown sessionId");
    }

    RegisterResponse registerResponse = RawMessageCodec
            .decodeRegisterResponse(registrationResponse.getRegistrationData());
    X509Certificate attestationCertificate = registerResponse.getAttestationCertificate();
    checkIsTrusted(attestationCertificate);

    byte[] clientData = checkClientData(registrationResponse.getBd(), "navigator.id.finishEnrollment", sessionData);
    byte[] userPublicKey = registerResponse.getUserPublicKey();
    byte[] keyHandle = registerResponse.getKeyHandle();
    byte[] signedBytes = RawMessageCodec.encodeRegistrationSignedBytes(
            crypto.hash(sessionData.getAppId()),
            crypto.hash(clientData),
            keyHandle,
            userPublicKey
    );
    crypto.checkSignature(attestationCertificate, signedBytes, registerResponse.getSignature());

    // The first time we create the SecurityKeyData, we set the counter value to 0.
    // We don't actually know what the counter value of the real device is - but it will
    // be something bigger (or equal) to 0, so subsequent signatures will check out ok.
    SecurityKeyData securityKeyData = new SecurityKeyData(
            currentTimeInMillis,
            keyHandle,
            userPublicKey,
            attestationCertificate,
            INITIAL_COUNTER_VALUE
    );
    dataStore.addSecurityKeyData(sessionData.getAccountName(), securityKeyData);
    return securityKeyData;
  }

  private void checkIsTrusted(X509Certificate attestationCertificate) {
    Set<X509Certificate> trustedCertificates = dataStore.getTrustedCertificates();
    if (!trustedCertificates.contains(attestationCertificate)) {
      Log.warning("Attestation cert is not trusted"); // TODO: Should this be more than a warning?
    }
  }

  @Override
  public List<SignRequest> getSignRequest(String accountName, String appId) throws U2fException {

    List<SecurityKeyData> securityKeyDataList = dataStore.getSecurityKeyData(accountName);
    ImmutableList.Builder<SignRequest> result = ImmutableList.builder();
    
    for (SecurityKeyData securityKeyData : securityKeyDataList) {
      byte[] challenge = challengeGenerator.generateChallenge(accountName);

      String sessionId = dataStore.storeSessionData(
              new SignSessionData(accountName, appId, challenge, securityKeyData.getPublicKey())
      );

      SignRequest signRequest = new SignRequest(
              U2F_VERSION,
              Base64.encodeBase64URLSafeString(challenge),
              appId,
              Base64.encodeBase64URLSafeString(securityKeyData.getKeyHandle()),
              sessionId
      );
      result.add(signRequest);
    }
    return result.build();
  }

  @Override
  public SecurityKeyData processSignResponse(SignResponse signResponse) throws U2fException {

    SignSessionData sessionData = dataStore.getSignSessionData(signResponse.getSessionId());
    if (sessionData == null) {
      throw new U2fException("Unknown sessionId");
    }
    
    byte[] clientData = checkClientData(signResponse.getBd(), "navigator.id.getAssertion", sessionData);

    AuthenticateResponse authenticateResponse = RawMessageCodec.decodeAuthenticateResponse(signResponse.getSign());
    byte userPresence = authenticateResponse.getUserPresence();
    if (userPresence != UserPresenceVerifier.USER_PRESENT_FLAG) {
      throw new U2fException("User presence invalid during authentication");
    }

    int counter = authenticateResponse.getCounter();
    SecurityKeyData securityKeyData = loadSecurityKeyData(sessionData);
    if (counter <= securityKeyData.getCounter()) {
      throw new U2fException("Counter value smaller than expected!");
    }
    
    byte[] signedBytes = RawMessageCodec.encodeAuthenticateSignedBytes(
            crypto.hash(sessionData.getAppId()),
            userPresence,
            counter,
            crypto.hash(clientData)
    );
    crypto.checkSignature(
            crypto.decodePublicKey(securityKeyData.getPublicKey()),
            signedBytes,
            authenticateResponse.getSignature()
    );

    dataStore.updateSecurityKeyCounter(sessionData.getAccountName(), securityKeyData.getPublicKey(), counter);
    return securityKeyData;
  }

  private SecurityKeyData loadSecurityKeyData(SignSessionData sessionData) throws U2fException {
    for (SecurityKeyData temp : dataStore.getSecurityKeyData(sessionData.getAccountName())) {
      if (Arrays.equals(sessionData.getPublicKey(), temp.getPublicKey())) {
        return temp;
      }
    }
    throw new U2fException("No security keys registered for this user");
  }

  private byte[] checkClientData(String clientDataBase64, String messageType, EnrollSessionData sessionData)
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

    byte[] challengeFromClientData = Base64.decodeBase64(clientData.get(CHALLENGE_PARAM).getAsString());
    if (!Arrays.equals(challengeFromClientData, sessionData.getChallenge())) {
      throw new U2fException("Wrong challenge signed in clientData");
    }

    // TODO: Deal with ChannelID

    return clientDataBytes;
  }
  
  private void verifyOrigin(String origin) throws U2fException {
    if (!allowedOrigins.contains(canonicalizeOrigin(origin))) {
      throw new U2fException(origin +
          " is not a recognized home origin for this backend");
    }
  }

  @Override
  public List<SecurityKeyData> getAllSecurityKeys(String accountName) {
    return dataStore.getSecurityKeyData(accountName);
  }

  @Override
  public void removeSecurityKey(String accountName, byte[] publicKey)
      throws U2fException {
    dataStore.removeSecurityKey(accountName, publicKey);
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
