package com.yubico.webauthn

import java.util.Optional

import com.yubico.scalacheck.gen.JavaGenerators._
import com.yubico.webauthn.attestation.Attestation
import com.yubico.webauthn.attestation.Generators._
import com.yubico.webauthn.data.ByteArray
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor
import com.yubico.webauthn.data.AttestationType
import com.yubico.webauthn.data.Generators._
import org.scalacheck.Arbitrary
import org.scalacheck.Arbitrary.arbitrary


object Generators {

  implicit val arbitraryRegistrationResult: Arbitrary[RegistrationResult] = Arbitrary(for {
    attestationMetadata <- arbitrary[Optional[Attestation]]
    attestationTrusted <- arbitrary[Boolean]
    attestationType <- arbitrary[AttestationType]
    keyId <- arbitrary[PublicKeyCredentialDescriptor]
    publicKeyCose <- arbitrary[ByteArray]
    warnings <- arbitrary[java.util.List[String]]
  } yield RegistrationResult.builder()
    .keyId(keyId)
    .attestationTrusted(attestationTrusted)
    .attestationType(attestationType)
    .publicKeyCose(publicKeyCose)
    .attestationMetadata(attestationMetadata)
    .warnings(warnings)
    .build())

}
