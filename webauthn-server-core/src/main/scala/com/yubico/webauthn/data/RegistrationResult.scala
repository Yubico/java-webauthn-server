package com.yubico.webauthn.data

import java.util.Optional

import com.yubico.u2f.attestation.Attestation


case class RegistrationResult(
  keyId: PublicKeyCredentialDescriptor,
  attestationTrusted: Boolean,
  attestationType: AttestationType,
  attestationMetadata: Optional[Attestation],
  publicKeyCose: Array[Byte],
  warnings: List[String]
)
