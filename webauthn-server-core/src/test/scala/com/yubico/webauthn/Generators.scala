package com.yubico.webauthn

import com.yubico.scalacheck.gen.JavaGenerators._
import com.yubico.webauthn.attestation.Attestation
import com.yubico.webauthn.attestation.Generators._
import com.yubico.webauthn.data.AssertionExtensionInputs
import com.yubico.webauthn.data.AttestationType
import com.yubico.webauthn.data.AuthenticatorAssertionExtensionOutputs
import com.yubico.webauthn.data.AuthenticatorRegistrationExtensionOutputs
import com.yubico.webauthn.data.ByteArray
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs
import com.yubico.webauthn.data.ClientRegistrationExtensionOutputs
import com.yubico.webauthn.data.Generators._
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor
import com.yubico.webauthn.data.UserVerificationRequirement
import org.scalacheck.Arbitrary
import org.scalacheck.Arbitrary.arbitrary
import org.scalacheck.Gen

import java.util.Optional

object Generators {

  implicit val arbitraryAssertionResult: Arbitrary[AssertionResult] = Arbitrary(
    for {
      authenticatorExtensionOutputs <-
        arbitrary[Option[AuthenticatorAssertionExtensionOutputs]]
      clientExtensionOutputs <- arbitrary[ClientAssertionExtensionOutputs]
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
      .clientExtensionOutputs(clientExtensionOutputs)
      .assertionExtensionOutputs(authenticatorExtensionOutputs.orNull)
      .warnings(warnings)
      .build()
  )

  implicit val arbitraryRegistrationResult: Arbitrary[RegistrationResult] =
    Arbitrary(
      for {
        attestationMetadata <- arbitrary[Optional[Attestation]]
        attestationTrusted <- arbitrary[Boolean]
        attestationType <- arbitrary[AttestationType]
        authenticatorExtensionOutputs <-
          arbitrary[Option[AuthenticatorRegistrationExtensionOutputs]]
        clientExtensionOutputs <- arbitrary[ClientRegistrationExtensionOutputs]
        keyId <- arbitrary[PublicKeyCredentialDescriptor]
        publicKeyCose <- arbitrary[ByteArray]
        signatureCount <- arbitrary[Long]
        warnings <- arbitrary[java.util.List[String]]
      } yield RegistrationResult
        .builder()
        .keyId(keyId)
        .attestationTrusted(attestationTrusted)
        .attestationType(attestationType)
        .publicKeyCose(publicKeyCose)
        .signatureCount(signatureCount)
        .clientExtensionOutputs(clientExtensionOutputs)
        .authenticatorExtensionOutputs(authenticatorExtensionOutputs.orNull)
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

  implicit val arbitraryStartAssertionOptions
      : Arbitrary[StartAssertionOptions] = Arbitrary(
    for {
      extensions <- arbitrary[Option[AssertionExtensionInputs]]
      timeout <- Gen.option(Gen.posNum[Long])
      usernameOrUserHandle <- arbitrary[Option[Either[String, ByteArray]]]
      userVerification <- arbitrary[Option[UserVerificationRequirement]]
    } yield {
      val b = StartAssertionOptions.builder()
      extensions.foreach(b.extensions)
      timeout.foreach(b.timeout)
      usernameOrUserHandle.foreach {
        case Left(username)    => b.username(username)
        case Right(userHandle) => b.userHandle(userHandle)
      }
      userVerification.foreach(b.userVerification)
      b.build()
    }
  )

}
