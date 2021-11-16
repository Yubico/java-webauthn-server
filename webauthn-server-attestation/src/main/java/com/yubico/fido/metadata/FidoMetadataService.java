// Copyright (c) 2015-2021, Yubico AB
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

package com.yubico.fido.metadata;

import com.yubico.internal.util.CertificateParser;
import com.yubico.webauthn.data.ByteArray;
import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.NonNull;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@AllArgsConstructor(access = AccessLevel.PUBLIC)
public final class FidoMetadataService {

  @NonNull private final MetadataBLOBPayload blob;

  public Optional<MetadataBLOBPayloadEntry> findEntry(AAGUID aaguid) {
    if (aaguid.isZero()) {
      log.debug("findEntry(aaguid = {}) => ignoring zero AAGUID", aaguid);
      return Optional.empty();
    } else {
      final Optional<MetadataBLOBPayloadEntry> result =
          blob.getEntries().stream()
              .filter(entry -> aaguid.equals(entry.getAaguid().orElse(null)))
              .findAny();
      log.debug("findEntry(aaguid = {}) => {}", aaguid, result.isPresent() ? "found" : "not found");
      return result;
    }
  }

  /**
   * @param attestationCertificateChain
   * @return
   * @throws NoSuchAlgorithmException if the SHA-1 hash algorithm is not available.
   */
  public Optional<MetadataBLOBPayloadEntry> findEntry(
      List<X509Certificate> attestationCertificateChain) throws NoSuchAlgorithmException {
    for (X509Certificate cert : attestationCertificateChain) {
      final String subjectKeyIdentifierHex =
          new ByteArray(CertificateParser.computeSubjectKeyIdentifier(cert)).getHex();

      final Optional<MetadataBLOBPayloadEntry> certSubjectKeyIdentifierMatch =
          blob.getEntries().stream()
              .filter(
                  entry ->
                      entry.getAttestationCertificateKeyIdentifiers().stream()
                          .anyMatch(subjectKeyIdentifierHex::equals))
              .findAny();

      if (certSubjectKeyIdentifierMatch.isPresent()) {
        log.debug("findEntry(certKeyIdentifier = {}) => found", subjectKeyIdentifierHex);
        return certSubjectKeyIdentifierMatch;
      } else {
        log.debug("findEntry(certKeyIdentifier = {}) => not found", subjectKeyIdentifierHex);
      }
    }

    return Optional.empty();
  }
}
