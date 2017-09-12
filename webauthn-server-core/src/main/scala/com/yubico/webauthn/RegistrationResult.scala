package com.yubico.webauthn

import java.util.Optional

import com.yubico.u2f.attestation.MetadataObject
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor


case class RegistrationResult(
  keyId: PublicKeyCredentialDescriptor,
  attestationTrusted: Boolean,
  attestationMetadata: Optional[MetadataObject]
)
