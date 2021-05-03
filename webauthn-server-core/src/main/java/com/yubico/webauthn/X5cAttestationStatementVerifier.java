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

package com.yubico.webauthn;

import com.fasterxml.jackson.databind.JsonNode;
import com.yubico.internal.util.CertificateParser;
import com.yubico.webauthn.data.AttestationObject;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

interface X5cAttestationStatementVerifier {

  default Optional<X509Certificate> getX5cAttestationCertificate(
      AttestationObject attestationObject) throws CertificateException {
    return getAttestationTrustPath(attestationObject).flatMap(certs -> certs.stream().findFirst());
  }

  default Optional<List<X509Certificate>> getAttestationTrustPath(
      AttestationObject attestationObject) throws CertificateException {
    JsonNode x5cNode = getX5cArray(attestationObject);

    if (x5cNode != null && x5cNode.isArray()) {
      List<X509Certificate> certs = new ArrayList<>(x5cNode.size());

      for (JsonNode binary : x5cNode) {
        if (binary.isBinary()) {
          try {
            certs.add(CertificateParser.parseDer(binary.binaryValue()));
          } catch (IOException e) {
            throw new RuntimeException(
                "binary.isBinary() was true but binary.binaryValue() failed", e);
          }
        } else {
          throw new IllegalArgumentException(
              String.format(
                  "Each element of \"x5c\" property of attestation statement must be a binary value, was: %s",
                  binary.getNodeType()));
        }
      }

      return Optional.of(certs);
    } else {
      return Optional.empty();
    }
  }

  default JsonNode getX5cArray(AttestationObject attestationObject) {
    return attestationObject.getAttestationStatement().get("x5c");
  }
}
