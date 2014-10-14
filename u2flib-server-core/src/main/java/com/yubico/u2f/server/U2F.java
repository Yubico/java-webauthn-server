package com.yubico.u2f.server;

import com.google.common.base.Optional;
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
import com.yubico.u2f.server.messages.AuthenticationResponse;
import com.yubico.u2f.server.messages.RegistrationResponse;
import org.apache.commons.codec.binary.Base64;

import java.security.cert.X509Certificate;
import java.util.Set;

public class U2F {

  private static final String U2F_VERSION = "U2F_V2";
  private static final ChallengeGenerator challengeGenerator = new ChallengeGeneratorImpl();
  private final static Crypto crypto = new BouncyCastleCrypto();
  public static final int INITIAL_COUNTER_VALUE = 0;

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
  public static Device finishRegistration(StartedRegistration startedRegistration, RegistrationResponse tokenResponse) throws U2fException {
    return finishRegistration(startedRegistration, tokenResponse, null);
  }

  public static Device finishRegistration(StartedRegistration startedRegistration, RegistrationResponse tokenResponse, Set<String> facets) throws U2fException {
    byte[] clientData = ClientDataUtils.checkClientData(
            tokenResponse.getClientData().toString(),
            "navigator.id.finishEnrollment",
            startedRegistration.getChallenge(),
            Optional.fromNullable(facets)
    );

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

    return new Device(
            keyHandle,
            userPublicKey,
            attestationCertificate,
            INITIAL_COUNTER_VALUE
    );
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
   * @param tokenResponse the response from the token/client.
   * @return the new value of the Device's counter.
   */
  public static int finishAuthentication(StartedAuthentication startedAuthentication, AuthenticationResponse tokenResponse, Device device) throws U2fException {
    return finishAuthentication(startedAuthentication, tokenResponse, device, null);
  }

  public static int finishAuthentication(StartedAuthentication startedAuthentication, AuthenticationResponse tokenResponse, Device device, Set<String> facets) throws U2fException {
    byte[] clientData = ClientDataUtils.checkClientData(
            tokenResponse.getClientData().toString(),
            "navigator.id.getAssertion",
            startedAuthentication.getChallenge(),
            Optional.fromNullable(facets)
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
}
