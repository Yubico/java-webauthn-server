/*
 * Copyright 2014 Yubico.
 * Copyright 2014 Google Inc. All rights reserved.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */

package com.yubico.u2f.data.messages.key;

import com.yubico.u2f.exceptions.U2fException;
import com.yubico.u2f.data.messages.key.util.ByteSink;

import java.security.cert.CertificateEncodingException;

public class CodecTestUtils {
  public static byte[] encodeAuthenticateResponse(RawAuthenticateResponse rawAuthenticateResponse) throws U2fException {
    return ByteSink.create()
            .put(rawAuthenticateResponse.getUserPresence())
            .putInt(rawAuthenticateResponse.getCounter())
            .put(rawAuthenticateResponse.getSignature())
            .toByteArray();
  }

  public static byte[] encodeRegisterResponse(RawRegisterResponse rawRegisterResponse) throws U2fException {
    byte[] keyHandle = rawRegisterResponse.keyHandle;
    if (keyHandle.length > 255) {
      throw new U2fException("keyHandle length cannot be longer than 255 bytes!");
    }

    try {
      return ByteSink.create()
              .put(RawRegisterResponse.REGISTRATION_RESERVED_BYTE_VALUE)
              .put(rawRegisterResponse.userPublicKey)
              .put((byte) keyHandle.length)
              .put(keyHandle)
              .put(rawRegisterResponse.attestationCertificate.getEncoded())
              .put(rawRegisterResponse.signature)
              .toByteArray();
    } catch (CertificateEncodingException e) {
      throw new U2fException("Error when encoding attestation certificate.", e);
    }
  }
}
