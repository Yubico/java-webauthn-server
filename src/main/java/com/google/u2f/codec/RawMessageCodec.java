// Copyright 2014 Google Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package com.google.u2f.codec;

import com.google.u2f.U2FException;
import com.google.u2f.key.messages.AuthenticateRequest;
import com.google.u2f.key.messages.AuthenticateResponse;
import com.google.u2f.key.messages.RegisterRequest;
import com.google.u2f.key.messages.RegisterResponse;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

/**
 * Raw message formats, as per FIDO U2F: Raw Message Formats - Draft 4
 */
public class RawMessageCodec {
  public static final byte REGISTRATION_RESERVED_BYTE_VALUE = (byte) 0x05;
  public static final byte REGISTRATION_SIGNED_RESERVED_BYTE_VALUE = (byte) 0x00;

  public static byte[] encodeRegisterRequest(RegisterRequest registerRequest) {
    byte[] appIdSha256 = registerRequest.getApplicationSha256();
    byte[] challengeSha256 = registerRequest.getChallengeSha256();

    return ByteSink.create()
            .put(challengeSha256)
            .put(appIdSha256)
            .toByteArray();
  }

  public static RegisterRequest decodeRegisterRequest(byte[] data) throws U2FException {
    try {
      ByteInputStream bytes = new ByteInputStream(data);
      byte[] challengeSha256 = bytes.read(32);
      byte[] appIdSha256 = bytes.read(32);

      if (!bytes.isExhausted()) {
        throw new U2FException("Message ends with unexpected data");
      }

      return new RegisterRequest(appIdSha256, challengeSha256);
    } catch (IOException e) {
      throw new U2FException("Error when parsing raw RegistrationResponse", e);
    }
  }

  public static byte[] encodeRegisterResponse(RegisterResponse registerResponse)
      throws U2FException {
    byte[] userPublicKey = registerResponse.getUserPublicKey();
    byte[] keyHandle = registerResponse.getKeyHandle();
    X509Certificate attestationCertificate = registerResponse.getAttestationCertificate();
    byte[] signature = registerResponse.getSignature();

    byte[] attestationCertificateBytes;
    try {
      attestationCertificateBytes = attestationCertificate.getEncoded();
    } catch (CertificateEncodingException e) {
      throw new U2FException("Error when encoding attestation certificate.", e);
    }

    if (keyHandle.length > 255) {
      throw new U2FException("keyHandle length cannot be longer than 255 bytes!");
    }

    return ByteSink.create()
            .put(REGISTRATION_RESERVED_BYTE_VALUE)
            .put(userPublicKey)
            .put((byte) keyHandle.length)
            .put(keyHandle)
            .put(attestationCertificateBytes)
            .put(signature)
            .toByteArray();
  }

  public static RegisterResponse decodeRegisterResponse(byte[] data) throws U2FException {
    try {
      ByteInputStream bytes = new ByteInputStream(data);
      byte reservedByte = bytes.readSigned();
      byte[] userPublicKey = bytes.read(65);
      byte[] keyHandle = bytes.read(bytes.readUnsigned());
      X509Certificate attestationCertificate = (X509Certificate) CertificateFactory.getInstance(
          "X.509").generateCertificate(bytes);
      byte[] signature = bytes.readAll();

      if (reservedByte != REGISTRATION_RESERVED_BYTE_VALUE) {
        throw new U2FException(String.format(
            "Incorrect value of reserved byte. Expected: %d. Was: %d",
            REGISTRATION_RESERVED_BYTE_VALUE, reservedByte));
      }

      return new RegisterResponse(userPublicKey, keyHandle, attestationCertificate, signature);
    } catch (IOException e) {
      throw new U2FException("Error when parsing raw RegistrationResponse", e);
    } catch (CertificateException e) {
      throw new U2FException("Error when parsing attestation certificate", e);
    }
  }


  public static byte[] encodeAuthenticateRequest(AuthenticateRequest authenticateRequest)
      throws U2FException {
    byte controlByte = authenticateRequest.getControl();
    byte[] appIdSha256 = authenticateRequest.getApplicationSha256();
    byte[] challengeSha256 = authenticateRequest.getChallengeSha256();
    byte[] keyHandle = authenticateRequest.getKeyHandle();

    if (keyHandle.length > 255) {
      throw new U2FException("keyHandle length cannot be longer than 255 bytes!");
    }

    return ByteSink.create()
            .put(controlByte)
            .put(challengeSha256)
            .put(appIdSha256)
            .put((byte) keyHandle.length)
            .put(keyHandle)
            .toByteArray();
  }

  public static AuthenticateRequest decodeAuthenticateRequest(byte[] data) throws U2FException {
    try {
      ByteInputStream bytes = new ByteInputStream(data);
      byte controlByte = bytes.readByte();
      byte[] challengeSha256 = bytes.read(32);
      byte[] appIdSha256 = bytes.read(32);
      byte[] keyHandle = bytes.read(bytes.readUnsignedByte());

      return new AuthenticateRequest(controlByte, challengeSha256, appIdSha256, keyHandle);
    } catch (IOException e) {
      throw new U2FException("Error when parsing raw RegistrationResponse", e);
    }
  }

  public static byte[] encodeAuthenticateResponse(AuthenticateResponse authenticateResponse)
      throws U2FException {
    byte userPresence = authenticateResponse.getUserPresence();
    int counter = authenticateResponse.getCounter();
    byte[] signature = authenticateResponse.getSignature();

    return ByteSink.create()
            .put(userPresence)
            .putInt(counter)
            .put(signature)
            .toByteArray();
  }

  public static AuthenticateResponse decodeAuthenticateResponse(byte[] data) throws U2FException {
    try {
      ByteInputStream bytes = new ByteInputStream(data);
      byte userPresence = bytes.readSigned();
      int counter = bytes.readInt();
      byte[] signature = bytes.readAll();

      return new AuthenticateResponse(userPresence, counter, signature);
    } catch (IOException e) {
      throw new U2FException("Error when parsing rawSignData", e);
    }
  }

  public static byte[] encodeRegistrationSignedBytes(byte[] applicationSha256,
      byte[] challengeSha256, byte[] keyHandle, byte[] userPublicKey) {

    return ByteSink.create()
            .put(REGISTRATION_SIGNED_RESERVED_BYTE_VALUE)
            .put(applicationSha256)
            .put(challengeSha256)
            .put(keyHandle)
            .put(userPublicKey)
            .toByteArray();
  }

  public static byte[] encodeAuthenticateSignedBytes(byte[] applicationSha256, byte userPresence,
      int counter, byte[] challengeSha256) {

    return ByteSink.create()
            .put(applicationSha256)
            .put(userPresence)
            .putInt(counter)
            .put(challengeSha256)
            .toByteArray();
  }
}
