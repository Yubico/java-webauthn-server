/*
 * Copyright 2014 Yubico.
 * Copyright 2014 Google Inc. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */

package com.yubico.u2f.codec;

import com.yubico.u2f.U2fException;
import com.yubico.u2f.key.messages.AuthenticateResponse;
import com.yubico.u2f.key.messages.RegisterResponse;

import java.security.cert.CertificateEncodingException;

public class CodecTestUtils {
  public static byte[] encodeAuthenticateResponse(AuthenticateResponse authenticateResponse) throws U2fException {
    return ByteSink.create()
            .put(authenticateResponse.getUserPresence())
            .putInt(authenticateResponse.getCounter())
            .put(authenticateResponse.getSignature())
            .toByteArray();
  }

  public static byte[] encodeRegisterResponse(RegisterResponse registerResponse) throws U2fException {
    byte[] keyHandle = registerResponse.getKeyHandle();
    if (keyHandle.length > 255) {
      throw new U2fException("keyHandle length cannot be longer than 255 bytes!");
    }

    try {
      return ByteSink.create()
              .put(RawMessageCodec.REGISTRATION_RESERVED_BYTE_VALUE)
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
}
