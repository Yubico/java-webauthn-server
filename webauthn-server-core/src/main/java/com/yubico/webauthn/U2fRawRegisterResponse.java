// Copyright (c) 2014-2018, Yubico AB
// Copyright (c) 2014, Google Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// 3. Neither the name of Google Inc. nor the names of its contributors may be
//    used to endorse or promote products derived from this software without
//    specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package com.yubico.webauthn;

import com.google.common.io.ByteArrayDataOutput;
import com.google.common.io.ByteStreams;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.COSEAlgorithmIdentifier;
import java.security.cert.X509Certificate;
import lombok.Value;

/** The register response produced by the token/key */
@Value
class U2fRawRegisterResponse {
  private static final byte REGISTRATION_SIGNED_RESERVED_BYTE_VALUE = (byte) 0x00;

  /** The (uncompressed) x,y-representation of a curve point on the P-256 NIST elliptic curve. */
  private final ByteArray userPublicKey;

  /** A handle that allows the U2F token to identify the generated key pair. */
  private final ByteArray keyHandle;

  private final X509Certificate attestationCertificate;

  /** A ECDSA signature (on P-256) */
  private final ByteArray signature;

  U2fRawRegisterResponse(
      ByteArray userPublicKey,
      ByteArray keyHandle,
      X509Certificate attestationCertificate,
      ByteArray signature) {
    this.userPublicKey = userPublicKey;
    this.keyHandle = keyHandle;
    this.attestationCertificate = attestationCertificate;
    this.signature = signature;
  }

  boolean verifySignature(ByteArray appIdHash, ByteArray clientDataHash) {
    ByteArray signedBytes = packBytesToSign(appIdHash, clientDataHash, keyHandle, userPublicKey);
    return Crypto.verifySignature(
        attestationCertificate, signedBytes, signature, COSEAlgorithmIdentifier.ES256);
  }

  private static ByteArray packBytesToSign(
      ByteArray appIdHash, ByteArray clientDataHash, ByteArray keyHandle, ByteArray userPublicKey) {
    ByteArrayDataOutput encoded = ByteStreams.newDataOutput();
    encoded.write(REGISTRATION_SIGNED_RESERVED_BYTE_VALUE);
    encoded.write(appIdHash.getBytes());
    encoded.write(clientDataHash.getBytes());
    encoded.write(keyHandle.getBytes());
    encoded.write(userPublicKey.getBytes());
    return new ByteArray(encoded.toByteArray());
  }
}
