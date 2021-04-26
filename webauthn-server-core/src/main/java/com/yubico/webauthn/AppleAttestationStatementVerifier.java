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

import com.yubico.internal.util.ExceptionUtil;
import com.yubico.webauthn.data.AttestationObject;
import com.yubico.webauthn.data.AttestationType;
import com.yubico.webauthn.data.ByteArray;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Optional;
import lombok.extern.slf4j.Slf4j;

@Slf4j
final class AppleAttestationStatementVerifier
    implements AttestationStatementVerifier, X5cAttestationStatementVerifier {

  private static final String NONCE_EXTENSION_OID = "1.2.840.113635.100.8.2";

  @Override
  public AttestationType getAttestationType(AttestationObject attestation) {
    return AttestationType.ANONYMIZATION_CA;
  }

  @Override
  public boolean verifyAttestationSignature(
      AttestationObject attestationObject, ByteArray clientDataJsonHash) {
    final Optional<X509Certificate> attestationCert;
    try {
      attestationCert = getX5cAttestationCertificate(attestationObject);
    } catch (CertificateException e) {
      throw ExceptionUtil.wrapAndLog(
          log,
          String.format(
              "Failed to parse X.509 certificate from attestation object: %s", attestationObject),
          e);
    }

    return attestationCert
        .map(
            attestationCertificate -> {
              final ByteArray nonceToHash =
                  attestationObject.getAuthenticatorData().getBytes().concat(clientDataJsonHash);

              final ByteArray nonce = Crypto.sha256(nonceToHash);

              byte[] nonceExtension = attestationCertificate.getExtensionValue(NONCE_EXTENSION_OID);
              if (nonceExtension == null) {
                throw new IllegalArgumentException(
                    "Apple anonymous attestation certificate must contain extension OID: "
                        + NONCE_EXTENSION_OID);
              }

              // X.509 extension values is a DER octet string: 0x0426
              // Then the extension contains a 1-element sequence: 0x3024
              // The element has context-specific tag "[1]": 0xa122
              // Then the sequence contains a 32-byte octet string: 0x0420
              final ByteArray expectedExtensionValue =
                  new ByteArray(
                          new byte[] {
                            0x04, 0x26, 0x30, 0x24, (-128) + (0xa1 - 128), 0x22, 0x04, 0x20
                          })
                      .concat(nonce);

              if (!expectedExtensionValue.equals(new ByteArray(nonceExtension))) {
                throw new IllegalArgumentException(
                    String.format(
                        "Apple anonymous attestation certificate extension %s must equal nonceToHash. Expected: %s, was: %s",
                        NONCE_EXTENSION_OID,
                        expectedExtensionValue,
                        new ByteArray(nonceExtension)));
              }

              final PublicKey credentialPublicKey;
              try {
                credentialPublicKey =
                    WebAuthnCodecs.importCosePublicKey(
                        attestationObject
                            .getAuthenticatorData()
                            .getAttestedCredentialData()
                            .get()
                            .getCredentialPublicKey());
              } catch (Exception e) {
                throw ExceptionUtil.wrapAndLog(log, "Failed to import credential public key", e);
              }

              final PublicKey certPublicKey = attestationCertificate.getPublicKey();

              if (!credentialPublicKey.equals(certPublicKey)) {
                throw new IllegalArgumentException(
                    String.format(
                        "Apple anonymous attestation certificate subject public key must equal credential public key. Expected: %s, was: %s",
                        credentialPublicKey, certPublicKey));
              }

              return true;
            })
        .orElseThrow(
            () ->
                new IllegalArgumentException(
                    "Failed to parse attestation certificate from \"apple\" attestation statement."));
  }
}
