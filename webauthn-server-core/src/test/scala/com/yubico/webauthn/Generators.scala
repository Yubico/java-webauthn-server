package com.yubico.webauthn

import com.yubico.scalacheck.gen.JavaGenerators._
import com.yubico.webauthn.attestation.Attestation
import com.yubico.webauthn.attestation.Generators._
import com.yubico.webauthn.data.AttestationType
import com.yubico.webauthn.data.ByteArray
import com.yubico.webauthn.data.Generators._
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor
import org.scalacheck.Arbitrary
import org.scalacheck.Arbitrary.arbitrary

import java.util.Optional

object Generators {

  implicit val arbitraryAssertionResult: Arbitrary[AssertionResult] = Arbitrary(
    for {
      credentialId <- arbitrary[ByteArray]
      signatureCount <- arbitrary[Long]
      signatureCounterValid <- arbitrary[Boolean]
      success <- arbitrary[Boolean]
      userHandle <- arbitrary[ByteArray]
      username <- arbitrary[String]
      warnings <- arbitrary[java.util.List[String]]
    } yield AssertionResult
      .builder()
      .success(success)
      .credentialId(credentialId)
      .userHandle(userHandle)
      .username(username)
      .signatureCount(signatureCount)
      .signatureCounterValid(signatureCounterValid)
      .warnings(warnings)
      .build()
  )

  implicit val arbitraryRegistrationResult: Arbitrary[RegistrationResult] =
    Arbitrary(
      for {
        attestationMetadata <- arbitrary[Optional[Attestation]]
        attestationTrusted <- arbitrary[Boolean]
        attestationType <- arbitrary[AttestationType]
        keyId <- arbitrary[PublicKeyCredentialDescriptor]
        publicKeyCose <- arbitrary[ByteArray]
        warnings <- arbitrary[java.util.List[String]]
      } yield RegistrationResult
        .builder()
        .keyId(keyId)
        .attestationTrusted(attestationTrusted)
        .attestationType(attestationType)
        .publicKeyCose(publicKeyCose)
        .attestationMetadata(attestationMetadata)
        .warnings(warnings)
        .build()
    )

  implicit val arbitraryRegisteredCredential: Arbitrary[RegisteredCredential] =
    Arbitrary(
      for {
        credentialId <- arbitrary[ByteArray]
        userHandle <- arbitrary[ByteArray]
        publicKeyCose <- arbitrary[ByteArray]
        signatureCount <- arbitrary[Int]
      } yield RegisteredCredential
        .builder()
        .credentialId(credentialId)
        .userHandle(userHandle)
        .publicKeyCose(publicKeyCose)
        .signatureCount(signatureCount)
        .build()
    )

}
