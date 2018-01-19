package com.yubico.webauthn

import java.util.Optional

import com.fasterxml.jackson.databind.node.ObjectNode
import com.yubico.u2f.attestation.Attestation
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor
import com.yubico.webauthn.data.AttestationType


case class RegistrationResult(
  keyId: PublicKeyCredentialDescriptor,
  attestationTrusted: Boolean,
  attestationType: AttestationType,
  attestationMetadata: Optional[Attestation],
  publicKeyCose: ObjectNode
)
