// Copyright (c) 2018, Yubico AB
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

package com.yubico.webauthn.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;

/**
 * Attested credential data is a variable-length byte array added to the authenticator data when
 * generating an attestation object for a given credential. This class provides access to the three
 * data segments of that byte array.
 *
 * @see <a
 *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-attested-credential-data">6.4.1.
 *     Attested Credential Data</a>
 */
@Value
@Builder(toBuilder = true)
public class AttestedCredentialData {

  /** The AAGUID of the authenticator. */
  @NonNull private final ByteArray aaguid;

  /** The credential ID of the attested credential. */
  @NonNull private final ByteArray credentialId;

  /**
   * The credential public key encoded in COSE_Key format, as defined in Section 7 of <a
   * href="https://tools.ietf.org/html/rfc8152">RFC 8152</a>.
   */
  @NonNull
  // TODO: verify requirements
  // https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-attested-credential-data
  private final ByteArray credentialPublicKey;

  @JsonCreator
  private AttestedCredentialData(
      @NonNull @JsonProperty("aaguid") ByteArray aaguid,
      @NonNull @JsonProperty("credentialId") ByteArray credentialId,
      @NonNull @JsonProperty("credentialPublicKey") ByteArray credentialPublicKey) {
    this.aaguid = aaguid;
    this.credentialId = credentialId;
    this.credentialPublicKey = credentialPublicKey;
  }

  static AttestedCredentialDataBuilder builder() {
    return new AttestedCredentialDataBuilder();
  }

  static class AttestedCredentialDataBuilder {}
}
