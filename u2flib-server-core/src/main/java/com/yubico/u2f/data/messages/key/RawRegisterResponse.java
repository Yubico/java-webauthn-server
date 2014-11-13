/*
 * Copyright 2014 Yubico.
 * Copyright 2014 Google Inc. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */

package com.yubico.u2f.data.messages.key;

import com.google.common.base.Objects;
import com.yubico.u2f.U2F;
import com.yubico.u2f.crypto.BouncyCastleCrypto;
import com.yubico.u2f.crypto.Crypto;
import com.yubico.u2f.data.DeviceRegistration;
import com.yubico.u2f.exceptions.U2fException;
import com.yubico.u2f.data.messages.key.util.ByteInputStream;
import com.yubico.u2f.data.messages.key.util.ByteSink;
import org.apache.commons.codec.binary.Base64;

import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;

/**
 * The register response produced by the token/key, which is transformed by the client into an RegisterResponse
 * and sent to the server.
 */
public class RawRegisterResponse {
  public static final byte REGISTRATION_RESERVED_BYTE_VALUE = (byte) 0x05;
  public static final byte REGISTRATION_SIGNED_RESERVED_BYTE_VALUE = (byte) 0x00;

  private final Crypto crypto;

  /**
   * The (uncompressed) x,y-representation of a curve point on the P-256
   * NIST elliptic curve.
   */
  final byte[] userPublicKey;

  /**
   * A handle that allows the U2F token to identify the generated key pair.
   */
  final byte[] keyHandle;
  final X509Certificate attestationCertificate;

  /** A ECDSA signature (on P-256) */
  final byte[] signature;

  public RawRegisterResponse(byte[] userPublicKey,
                             byte[] keyHandle,
                             X509Certificate attestationCertificate,
                             byte[] signature) {
    this(userPublicKey, keyHandle, attestationCertificate, signature, new BouncyCastleCrypto());
  }

  public RawRegisterResponse(byte[] userPublicKey,
                             byte[] keyHandle,
                             X509Certificate attestationCertificate,
                             byte[] signature,
                             Crypto crypto) {
    this.userPublicKey = userPublicKey;
    this.keyHandle = keyHandle;
    this.attestationCertificate = attestationCertificate;
    this.signature = signature;
    this.crypto = crypto;
  }

  public static RawRegisterResponse fromBase64(String rawDataBase64, Crypto crypto) throws U2fException {
    ByteInputStream bytes = new ByteInputStream(Base64.decodeBase64(rawDataBase64));
    byte reservedByte = bytes.readSigned();
    if (reservedByte != REGISTRATION_RESERVED_BYTE_VALUE) {
      throw new U2fException(
              "Incorrect value of reserved byte. Expected: " + REGISTRATION_RESERVED_BYTE_VALUE +
              ". Was: " + reservedByte
      );
    }

    try {
      return new RawRegisterResponse(
              bytes.read(65),
              bytes.read(bytes.readUnsigned()),
              (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(bytes),
              bytes.readAll(),
              crypto
      );
    } catch (CertificateException e) {
      throw new U2fException("Error when parsing attestation certificate", e);
    }
  }

  public void checkSignature(String appId, String clientData) throws U2fException {
    byte[] signedBytes = packBytesToSign(crypto.hash(appId), crypto.hash(clientData), keyHandle, userPublicKey);
    crypto.checkSignature(attestationCertificate, signedBytes, signature);
  }

  public static byte[] packBytesToSign(byte[] appIdHash, byte[] clientDataHash, byte[] keyHandle, byte[] userPublicKey) {
    return ByteSink.create()
              .put(REGISTRATION_SIGNED_RESERVED_BYTE_VALUE)
              .put(appIdHash)
              .put(clientDataHash)
              .put(keyHandle)
              .put(userPublicKey)
              .toByteArray();
  }

  public DeviceRegistration createDevice() throws U2fException {
    return new DeviceRegistration(
            Base64.encodeBase64URLSafeString(keyHandle),
            userPublicKey,
            attestationCertificate,
            DeviceRegistration.INITIAL_COUNTER_VALUE
    );
  }

  @Override
  public int hashCode() {
    return Objects.hashCode(userPublicKey, keyHandle, attestationCertificate, signature);
  }

  @Override
  public boolean equals(Object obj) {
    if (!(obj instanceof RawRegisterResponse))
      return false;
    RawRegisterResponse other = (RawRegisterResponse) obj;
    return Objects.equal(attestationCertificate, other.attestationCertificate)
            && Arrays.equals(keyHandle, other.keyHandle)
            && Arrays.equals(signature, other.signature)
            && Arrays.equals(userPublicKey, other.userPublicKey);
  }
}
