package com.yubico.webauthn

import java.util.Optional

import com.yubico.scalacheck.gen.JavaGenerators._
import com.yubico.webauthn.attestation.Attestation
import com.yubico.webauthn.attestation.Generators._
import com.yubico.webauthn.data.ByteArray
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor
import com.yubico.webauthn.data.AttestationType
import com.yubico.webauthn.data.CredentialRevocation
import com.yubico.webauthn.data.Generators._
import com.yubico.webauthn.data.RecoveryCredentialsState
import org.scalacheck.Arbitrary
import org.scalacheck.Arbitrary.arbitrary


object Generators {

  implicit val arbitraryAssertionResult: Arbitrary[AssertionResult] = Arbitrary(for {
    credentialId <- arbitrary[ByteArray]
    signatureCount <- arbitrary[Long]
    signatureCounterValid <- arbitrary[Boolean]
    success <- arbitrary[Boolean]
    userHandle <- arbitrary[ByteArray]
    username <- arbitrary[String]
    newRecoveryState <- arbitrary[Boolean]
    recoveryState <- arbitrary[Optional[RecoveryCredentialsState]]
    warnings <- arbitrary[java.util.List[String]]
  } yield AssertionResult.builder()
    .success(success)
    .credentialId(credentialId)
    .userHandle(userHandle)
    .username(username)
    .signatureCount(signatureCount)
    .signatureCounterValid(signatureCounterValid)
    .newRecoveryState(newRecoveryState)
    .newRecoveryCredentialsState(recoveryState)
    .warnings(warnings)
    .build())

  implicit val arbitraryRegistrationResult: Arbitrary[RegistrationResult] = Arbitrary(for {
    attestationMetadata <- arbitrary[Optional[Attestation]]
    attestationTrusted <- arbitrary[Boolean]
    attestationType <- arbitrary[AttestationType]
    keyId <- arbitrary[PublicKeyCredentialDescriptor]
    publicKeyCose <- arbitrary[ByteArray]
    recoveryRevocation <- arbitrary[Optional[CredentialRevocation]]
    warnings <- arbitrary[java.util.List[String]]
  } yield RegistrationResult.builder()
    .keyId(keyId)
    .attestationTrusted(attestationTrusted)
    .attestationType(attestationType)
    .publicKeyCose(publicKeyCose)
    .attestationMetadata(attestationMetadata)
    .recoveryRevocation(recoveryRevocation.orElse(null))
    .warnings(warnings)
    .build())

}
