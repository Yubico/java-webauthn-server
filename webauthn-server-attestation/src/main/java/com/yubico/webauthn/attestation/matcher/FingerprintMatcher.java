// Copyright (c) 2015-2018, Yubico AB
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

package com.yubico.webauthn.attestation.matcher;

import com.fasterxml.jackson.databind.JsonNode;
import com.google.common.hash.Hashing;
import com.yubico.webauthn.attestation.DeviceMatcher;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

public final class FingerprintMatcher implements DeviceMatcher {
  public static final String SELECTOR_TYPE = "fingerprint";

  private static final String FINGERPRINTS_KEY = "fingerprints";

  @Override
  public boolean matches(X509Certificate attestationCertificate, JsonNode parameters) {
    JsonNode fingerprints = parameters.get(FINGERPRINTS_KEY);
    if (fingerprints.isArray()) {
      try {
        String fingerprint =
            Hashing.sha1().hashBytes(attestationCertificate.getEncoded()).toString().toLowerCase();
        for (JsonNode candidate : fingerprints) {
          if (fingerprint.equals(candidate.asText().toLowerCase())) {
            return true;
          }
        }
      } catch (CertificateEncodingException e) {
        // Fall through to return false.
      }
    }
    return false;
  }
}
