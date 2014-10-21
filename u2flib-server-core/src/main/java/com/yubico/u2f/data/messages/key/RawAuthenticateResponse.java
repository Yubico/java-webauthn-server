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
import com.yubico.u2f.exceptions.U2fException;
import com.yubico.u2f.data.messages.key.util.ByteInputStream;
import com.yubico.u2f.data.messages.key.util.ByteSink;
import org.apache.commons.codec.binary.Base64;

import java.util.Arrays;

/**
 * The authenticate response produced by the token/key, which is transformed by the client into an AuthenticateResponse
 * and sent to the server.
 */
public class RawAuthenticateResponse {
  public static final byte USER_PRESENT_FLAG = 0x01;
  private final byte userPresence;
  private final int counter;
  private final byte[] signature;

  public RawAuthenticateResponse(byte userPresence, int counter, byte[] signature) {
    this.userPresence = userPresence;
    this.counter = counter;
    this.signature = signature;
  }

  public static RawAuthenticateResponse fromBase64(String rawDataBase64) throws U2fException {
    ByteInputStream bytes = new ByteInputStream(Base64.decodeBase64(rawDataBase64));
    return new RawAuthenticateResponse(
            bytes.readSigned(),
            bytes.readInteger(),
            bytes.readAll()
    );
  }

  public void checkSignature(String appId, byte[] clientData, byte[] publicKey) throws U2fException {
    byte[] signedBytes = packBytesToSign(
            U2F.crypto.hash(appId),
            userPresence,
            counter,
            U2F.crypto.hash(clientData)
    );
    U2F.crypto.checkSignature(
            U2F.crypto.decodePublicKey(publicKey),
            signedBytes,
            signature
    );
  }

  public static byte[] packBytesToSign(byte[] appIdHash, byte userPresence, int counter, byte[] challengeHash) {
    return ByteSink.create()
            .put(appIdHash)
            .put(userPresence)
            .putInt(counter)
            .put(challengeHash)
            .toByteArray();
  }

  /**
   * Bit 0 is set to 1, which means that user presence was verified. (This
   * version of the protocol doesn't specify a way to request authentication
   * responses without requiring user presence.) A different value of bit 0, as
   * well as bits 1 through 7, are reserved for future use. The values of bit 1
   * through 7 SHOULD be 0
   */
  public byte getUserPresence() {
    return userPresence;
  }

  /**
   * This is the big-endian representation of a counter value that the U2F device
   * increments every time it performs an authentication operation.
   */
  public int getCounter() {
    return counter;
  }

  /** This is a ECDSA signature (on P-256) */
  public byte[] getSignature() {
    return signature;
  }

  @Override
  public int hashCode() {
    return Objects.hashCode(userPresence, counter, signature);
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj)
      return true;
    if (obj == null)
      return false;
    if (getClass() != obj.getClass())
      return false;
    RawAuthenticateResponse other = (RawAuthenticateResponse) obj;
    if (counter != other.counter)
      return false;
    if (!Arrays.equals(signature, other.signature))
      return false;
    return userPresence == other.userPresence;
  }

  public void checkUserPresence() throws U2fException {
    if (userPresence != USER_PRESENT_FLAG) {
      throw new U2fException("User presence invalid during authentication");
    }
  }
}
