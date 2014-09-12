// Copyright 2014 Google Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file or at
// https://developers.google.com/open-source/licenses/bsd

package com.google.u2f.codec;

import com.google.u2f.U2fException;
import com.google.u2f.key.messages.AuthenticateRequest;
import com.google.u2f.key.messages.AuthenticateResponse;
import com.google.u2f.key.messages.RegisterRequest;
import com.google.u2f.key.messages.RegisterResponse;
import org.apache.commons.codec.binary.Base64;

import java.io.IOException;
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

    return ByteSink.create()
            .put(registerRequest.getChallengeHash())
            .put(registerRequest.getApplicationHash())
            .toByteArray();
  }

  public static RegisterRequest decodeRegisterRequest(byte[] data) throws U2fException {
    ByteInputStream bytes = new ByteInputStream(data);
    RegisterRequest registerRequest = new RegisterRequest(bytes.read(32), bytes.read(32));

    bytes.checkIsExhausted();

    return registerRequest;
  }

  public static byte[] encodeRegisterResponse(RegisterResponse registerResponse)
      throws U2fException {
    byte[] keyHandle = registerResponse.getKeyHandle();
    if (keyHandle.length > 255) {
      throw new U2fException("keyHandle length cannot be longer than 255 bytes!");
    }

    try {
      return ByteSink.create()
              .put(REGISTRATION_RESERVED_BYTE_VALUE)
              .put(registerResponse.getUserPublicKey())
              .put((byte) keyHandle.length)
              .put(keyHandle)
              .put(registerResponse.getAttestationCertificate().getEncoded())
              .put(registerResponse.getSignature())
              .toByteArray();
    } catch (CertificateEncodingException e) {
      throw new U2fException("Error when encoding attestation certificate.", e);
    }
  }

  public static RegisterResponse decodeRegisterResponse(String rawDataBase64) throws U2fException {
    return decodeRegisterResponse(Base64.decodeBase64(rawDataBase64));
  }

  public static RegisterResponse decodeRegisterResponse(byte[] data) throws U2fException {
    ByteInputStream bytes = new ByteInputStream(data);
    byte reservedByte = bytes.readSigned();
    if (reservedByte != REGISTRATION_RESERVED_BYTE_VALUE) {
      throw new U2fException(String.format(
          "Incorrect value of reserved byte. Expected: %d. Was: %d",
          REGISTRATION_RESERVED_BYTE_VALUE, reservedByte));
    }
    try {
      return new RegisterResponse(
              bytes.read(65),
              bytes.read(bytes.readUnsigned()),
              (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(bytes),
              bytes.readAll()
      );
    } catch (CertificateException e) {
      throw new U2fException("Error when parsing attestation certificate", e);
    }
  }

  public static byte[] encodeAuthenticateRequest(AuthenticateRequest authenticateRequest)
      throws U2fException {

    byte[] keyHandle = authenticateRequest.getKeyHandle();
    if (keyHandle.length > 255) {
      throw new U2fException("keyHandle cannot be longer than 255 bytes!");
    }

    return ByteSink.create()
            .put(authenticateRequest.getControl())
            .put(authenticateRequest.getChallengeHash())
            .put(authenticateRequest.getApplicationHash())
            .put((byte) keyHandle.length)
            .put(keyHandle)
            .toByteArray();
  }

  // TODO: Why is this only being used by tests?
  public static AuthenticateRequest decodeAuthenticateRequest(byte[] data) throws U2fException {
    try {
      ByteInputStream bytes = new ByteInputStream(data);
      return new AuthenticateRequest(
              bytes.readByte(),
              bytes.read(32),
              bytes.read(32),
              bytes.read(bytes.readUnsignedByte())
      );
    } catch (IOException e) {
      throw new U2fException("Error when parsing raw RegistrationResponse", e);
    }
  }

  // TODO: Why is this only being used by tests?
  public static byte[] encodeAuthenticateResponse(AuthenticateResponse authenticateResponse)
      throws U2fException {

    return ByteSink.create()
            .put(authenticateResponse.getUserPresence())
            .putInt(authenticateResponse.getCounter())
            .put(authenticateResponse.getSignature())
            .toByteArray();
  }

  public static AuthenticateResponse decodeAuthenticateResponse(String rawSignDataBase64) throws U2fException {
    return decodeAuthenticateResponse(Base64.decodeBase64(rawSignDataBase64));
  }

  public static AuthenticateResponse decodeAuthenticateResponse(byte[] data) throws U2fException {
    ByteInputStream bytes = new ByteInputStream(data);
    return new AuthenticateResponse(
            bytes.readSigned(),
            bytes.readInteger(),
            bytes.readAll()
    );
  }

  public static byte[] encodeRegistrationSignedBytes(byte[] applicationHash, byte[] challengeHash,
                                                     byte[] keyHandle, byte[] userPublicKey) {

    return ByteSink.create()
            .put(REGISTRATION_SIGNED_RESERVED_BYTE_VALUE)
            .put(applicationHash)
            .put(challengeHash)
            .put(keyHandle)
            .put(userPublicKey)
            .toByteArray();
  }

  public static byte[] encodeAuthenticateSignedBytes(byte[] applicationHash, byte userPresence,
                                                     int counter, byte[] challengeHash) {

    return ByteSink.create()
            .put(applicationHash)
            .put(userPresence)
            .putInt(counter)
            .put(challengeHash)
            .toByteArray();
  }
}