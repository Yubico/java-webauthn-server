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

import static com.yubico.webauthn.Crypto.isP256;

import COSE.CoseException;
import com.fasterxml.jackson.databind.JsonNode;
import com.yubico.internal.util.ExceptionUtil;
import com.yubico.webauthn.data.AttestationObject;
import com.yubico.webauthn.data.AttestationType;
import com.yubico.webauthn.data.AttestedCredentialData;
import com.yubico.webauthn.data.ByteArray;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Optional;
import lombok.extern.slf4j.Slf4j;

@Slf4j
final class FidoU2fAttestationStatementVerifier
    implements AttestationStatementVerifier, X5cAttestationStatementVerifier {

  private X509Certificate getAttestationCertificate(AttestationObject attestationObject)
      throws CertificateException {
    return getX5cAttestationCertificate(attestationObject)
        .map(
            attestationCertificate -> {
              if ("EC".equals(attestationCertificate.getPublicKey().getAlgorithm())
                  && isP256(((ECPublicKey) attestationCertificate.getPublicKey()).getParams())) {
                return attestationCertificate;
              } else {
                throw new IllegalArgumentException(
                    "Attestation certificate for fido-u2f must have an ECDSA P-256 public key.");
              }
            })
        .orElseThrow(
            () ->
                new IllegalArgumentException(
                    "fido-u2f attestation statement must have an \"x5c\" property set to an array of at least one DER encoded X.509 certificate."));
  }

  private static boolean validSelfSignature(X509Certificate cert) {
    try {
      cert.verify(cert.getPublicKey());
      return true;
    } catch (Exception e) {
      return false;
    }
  }

  private static ByteArray getRawUserPublicKey(AttestationObject attestationObject)
      throws IOException, CoseException {
    final ByteArray pubkeyCose =
        attestationObject
            .getAuthenticatorData()
            .getAttestedCredentialData()
            .get()
            .getCredentialPublicKey();
    final PublicKey pubkey;
    try {
      pubkey = WebAuthnCodecs.importCosePublicKey(pubkeyCose);
    } catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
      throw ExceptionUtil.wrapAndLog(log, "Failed to decode public key: " + pubkeyCose.getHex(), e);
    }

    final ECPublicKey ecPubkey;
    try {
      ecPubkey = (ECPublicKey) pubkey;
    } catch (ClassCastException e) {
      throw new RuntimeException("U2F supports only EC keys, was: " + pubkey);
    }

    return WebAuthnCodecs.ecPublicKeyToRaw(ecPubkey);
  }

  @Override
  public AttestationType getAttestationType(AttestationObject attestationObject)
      throws CoseException, IOException, CertificateException {
    X509Certificate attestationCertificate = getAttestationCertificate(attestationObject);

    if (attestationCertificate.getPublicKey() instanceof ECPublicKey
        && validSelfSignature(attestationCertificate)
        && getRawUserPublicKey(attestationObject)
            .equals(
                WebAuthnCodecs.ecPublicKeyToRaw(
                    (ECPublicKey) attestationCertificate.getPublicKey()))) {
      return AttestationType.SELF_ATTESTATION;
    } else {
      return AttestationType.BASIC;
    }
  }

  @Override
  public boolean verifyAttestationSignature(
      AttestationObject attestationObject, ByteArray clientDataJsonHash) {
    final X509Certificate attestationCertificate;
    try {
      attestationCertificate = getAttestationCertificate(attestationObject);
    } catch (CertificateException e) {
      throw new IllegalArgumentException(
          String.format(
              "Failed to parse X.509 certificate from attestation object: %s", attestationObject));
    }

    if (!("EC".equals(attestationCertificate.getPublicKey().getAlgorithm())
        && isP256(((ECPublicKey) attestationCertificate.getPublicKey()).getParams()))) {
      throw new IllegalArgumentException(
          "Attestation certificate for fido-u2f must have an ECDSA P-256 public key.");
    }

    final Optional<AttestedCredentialData> attData =
        attestationObject.getAuthenticatorData().getAttestedCredentialData();

    return attData
        .map(
            attestedCredentialData -> {
              JsonNode signature = attestationObject.getAttestationStatement().get("sig");

              if (signature == null) {
                throw new IllegalArgumentException(
                    "fido-u2f attestation statement must have a \"sig\" property set to a DER encoded signature.");
              }

              if (signature.isBinary()) {
                final ByteArray userPublicKey;

                try {
                  userPublicKey = getRawUserPublicKey(attestationObject);
                } catch (IOException | CoseException e) {
                  RuntimeException err =
                      new RuntimeException(
                          String.format(
                              "Failed to parse public key from attestation data %s",
                              attestedCredentialData),
                          e);
                  log.error(err.getMessage(), err);
                  throw err;
                }

                ByteArray keyHandle = attestedCredentialData.getCredentialId();

                U2fRawRegisterResponse u2fRegisterResponse;
                try {
                  u2fRegisterResponse =
                      new U2fRawRegisterResponse(
                          userPublicKey,
                          keyHandle,
                          attestationCertificate,
                          new ByteArray(signature.binaryValue()));
                } catch (IOException e) {
                  RuntimeException err =
                      new RuntimeException(
                          "signature.isBinary() was true but signature.binaryValue() failed", e);
                  log.error(err.getMessage(), err);
                  throw err;
                }

                return u2fRegisterResponse.verifySignature(
                    attestationObject.getAuthenticatorData().getRpIdHash(), clientDataJsonHash);
              } else {
                throw new IllegalArgumentException(
                    "\"sig\" property of fido-u2f attestation statement must be a CBOR byte array value.");
              }
            })
        .orElseThrow(
            () ->
                new IllegalArgumentException(
                    "Attestation object for credential creation must have attestation data."));
  }
}
