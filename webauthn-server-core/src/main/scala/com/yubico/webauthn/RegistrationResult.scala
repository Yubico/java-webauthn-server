package com.yubico.webauthn

import java.util.Optional

import com.yubico.u2f.attestation.MetadataObject
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor
import com.yubico.webauthn.data.AttestationType


case class RegistrationResult(
  keyId: PublicKeyCredentialDescriptor,
  attestationTrusted: Boolean,
  attestationType: AttestationType,
  attestationMetadata: Optional[MetadataObject]
)
