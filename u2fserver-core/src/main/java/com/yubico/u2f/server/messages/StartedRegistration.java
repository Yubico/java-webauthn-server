/*
 * Copyright 2014 Yubico.
 * Copyright 2014 Google Inc. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */

package com.yubico.u2f.server.messages;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.google.common.base.Objects;
import com.google.common.collect.ImmutableSet;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.yubico.u2f.U2fException;
import com.yubico.u2f.codec.RawMessageCodec;
import com.yubico.u2f.key.messages.RegisterResponse;
import com.yubico.u2f.server.ClientDataChecker;
import com.yubico.u2f.server.Crypto;
import com.yubico.u2f.server.data.Device;
import com.yubico.u2f.server.impl.BouncyCastleCrypto;
import org.apache.commons.codec.binary.Base64;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Logger;

public class StartedRegistration {
  /**
   * Version of the protocol that the to-be-registered U2F token must speak. For
   * the version of the protocol described herein, must be "U2F_V2"
   */
  @JsonProperty
  private final String version;

  /** The websafe-base64-encoded challenge. */
  @JsonProperty
  private final String challenge;

  public String getChallenge() {
    return challenge;
  }

  /**
   * The application id that the RP would like to assert. The U2F token will
   * enforce that the key handle provided above is associated with this
   * application id. The browser enforces that the calling origin belongs to the
   * application identified by the application id.
   */
  @JsonProperty
  private final String appId;

  private final Set<X509Certificate> trustedAttestationCertificates = new HashSet<X509Certificate>();

  private final Crypto crypto = new BouncyCastleCrypto();
  private final Set<String> allowedOrigins;

  public String getAppId() {
    return appId;
  }

  private static final Logger Log = Logger.getLogger(StartedRegistration.class.getName());

  public static final int INITIAL_COUNTER_VALUE = 0;

  public StartedRegistration(String version, String challenge, String appId, Set<String> origins) {
    this.version = version;
    this.challenge = challenge;
    this.appId = appId;
    this.allowedOrigins = ClientDataChecker.canonicalizeOrigins(origins);
  }

  @Override
  public int hashCode() {
    return Objects.hashCode(version, challenge, appId);
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;
    if (obj == null)
      return false;
    if (getClass() != obj.getClass())
      return false;
    StartedRegistration other = (StartedRegistration) obj;
    if (appId == null) {
      if (other.appId != null)
        return false;
    } else if (!appId.equals(other.appId))
      return false;
    if (challenge == null) {
      if (other.challenge != null)
        return false;
    } else if (!challenge.equals(other.challenge))
      return false;
    if (version == null) {
      if (other.version != null)
        return false;
    } else if (!version.equals(other.version))
      return false;
    return true;
  }

  public Device finish(TokenRegistrationResponse tokenRegistrationResponse) throws U2fException {
    RegisterResponse registerResponse = RawMessageCodec.decodeRegisterResponse(tokenRegistrationResponse.getRegistrationData());
    X509Certificate attestationCertificate = registerResponse.getAttestationCertificate();
    checkIsTrusted(attestationCertificate);

    byte[] clientData = ClientDataChecker.checkClientData(tokenRegistrationResponse.getClientData(), "navigator.id.finishEnrollment", challenge, allowedOrigins);
    byte[] userPublicKey = registerResponse.getUserPublicKey();
    byte[] keyHandle = registerResponse.getKeyHandle();
    byte[] signedBytes = RawMessageCodec.encodeRegistrationSignedBytes(
            crypto.hash(getAppId()),
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

  private void checkIsTrusted(X509Certificate attestationCertificate)  {
    if (!trustedAttestationCertificates.contains(attestationCertificate)) {
      Log.warning("Attestation cert is not trusted"); // TODO: Should this be more than a warning?
    }
  }


}
