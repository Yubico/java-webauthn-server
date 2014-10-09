package com.yubico.u2f.server;

import com.google.common.base.Optional;
import com.google.gson.Gson;
import com.yubico.u2f.U2fException;
import com.yubico.u2f.codec.RawMessageCodec;
import com.yubico.u2f.key.UserPresenceVerifier;
import com.yubico.u2f.key.messages.AuthenticateResponse;
import com.yubico.u2f.key.messages.RegisterResponse;
import com.yubico.u2f.server.data.Device;
import com.yubico.u2f.server.impl.BouncyCastleCrypto;
import com.yubico.u2f.server.impl.ChallengeGeneratorImpl;
import com.yubico.u2f.server.messages.StartedAuthentication;
import com.yubico.u2f.server.messages.StartedRegistration;
import com.yubico.u2f.server.messages.TokenAuthenticationResponse;
import com.yubico.u2f.server.messages.TokenRegistrationResponse;
import org.apache.commons.codec.binary.Base64;

import java.security.cert.X509Certificate;
import java.util.Set;

public class U2F {

  private static final String U2F_VERSION = "U2F_V2";
  private static final ChallengeGenerator challengeGenerator = new ChallengeGeneratorImpl();
  private final static Crypto crypto = new BouncyCastleCrypto();
  public static final int INITIAL_COUNTER_VALUE = 0;

  public static String startRegistration(String appId) {
    byte[] challenge = challengeGenerator.generateChallenge();
    String challengeBase64 = Base64.encodeBase64URLSafeString(challenge);
    return new StartedRegistration(U2F_VERSION, challengeBase64, appId).json();
  }

  public static String startAuthentication(String appId, Device device) {
    byte[] challenge = challengeGenerator.generateChallenge();
    return new StartedAuthentication(
            U2F_VERSION,
            Base64.encodeBase64URLSafeString(challenge),
            appId,
            Base64.encodeBase64URLSafeString(device.getKeyHandle())
    ).json();
  }

  public static Device finishRegistration(String startedRegistration, String tokenResponse, Set<String> allowedOrigins) throws U2fException {
    return finishRegistration(
            StartedRegistration.fromJson(startedRegistration),
            TokenRegistrationResponse.fromJson(tokenResponse),
            allowedOrigins
    );
  }

  public static Device finishRegistration(StartedRegistration startedRegistration, TokenRegistrationResponse tokenResponse, Set<String> allowedOrigins) throws U2fException {
    byte[] clientData = ClientDataChecker.checkClientData(tokenResponse.getClientData(), "navigator.id.finishEnrollment", startedRegistration.getChallenge(),
            Optional.of(ClientDataChecker.canonicalizeOrigins(allowedOrigins)));

    RegisterResponse registerResponse = RawMessageCodec.decodeRegisterResponse(tokenResponse.getRegistrationData());
    X509Certificate attestationCertificate = registerResponse.getAttestationCertificate();

    byte[] userPublicKey = registerResponse.getUserPublicKey();
    byte[] keyHandle = registerResponse.getKeyHandle();
    byte[] signedBytes = RawMessageCodec.encodeRegistrationSignedBytes(
            crypto.hash(startedRegistration.getAppId()),
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

  public static int finishAuthentication(StartedAuthentication startedAuthentication, TokenAuthenticationResponse tokenResponse, Device device, Set<String> allowedOrigins) throws U2fException {
    byte[] clientData = ClientDataChecker.checkClientData(
            tokenResponse.getClientData(),
            "navigator.id.getAssertion",
            startedAuthentication.getChallenge(),
            Optional.of(ClientDataChecker.canonicalizeOrigins(allowedOrigins))
    );

    AuthenticateResponse authenticateResponse = RawMessageCodec.decodeAuthenticateResponse(tokenResponse.getSignatureData());
    byte userPresence = authenticateResponse.getUserPresence();
    if (userPresence != UserPresenceVerifier.USER_PRESENT_FLAG) {
      throw new U2fException("User presence invalid during authentication");
    }

    int counter = authenticateResponse.getCounter();
    if (counter <= device.getCounter()) {
      throw new U2fException("Counter value smaller than expected!");
    }

    byte[] signedBytes = RawMessageCodec.encodeAuthenticateSignedBytes(
            crypto.hash(startedAuthentication.getAppId()),
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

  public static int finishAuthentication(String startedAuthentication, String tokenResponse, Device device, Set<String> allowedOrigins) throws U2fException {
    return finishAuthentication(
            StartedAuthentication.fromJson(startedAuthentication),
            TokenAuthenticationResponse.fromJson(tokenResponse),
            device,
            allowedOrigins
    );
  }

}
