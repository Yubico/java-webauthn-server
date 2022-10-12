package com.yubico.webauthn

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
import org.bouncycastle.asn1.x500.X500Name
import org.scalacheck.Arbitrary
import org.scalacheck.Arbitrary.arbitrary
import org.scalacheck.Gen

import java.security.cert.X509Certificate
import scala.jdk.CollectionConverters.SeqHasAsJava

object Generators {

  implicit val arbitraryAssertionResult: Arbitrary[AssertionResult] = Arbitrary(
    for {
      authenticatorExtensionOutputs <-
        arbitrary[Option[AuthenticatorAssertionExtensionOutputs]]
      clientExtensionOutputs <- arbitrary[ClientAssertionExtensionOutputs]
      credential <- arbitrary[RegisteredCredential]
      signatureCount <- arbitrary[Long]
      signatureCounterValid <- arbitrary[Boolean]
      success <- arbitrary[Boolean]
      username <- arbitrary[String]
    } yield AssertionResult
      .builder()
      .success(success)
      .credential(credential)
      .username(username)
      .signatureCount(signatureCount)
      .signatureCounterValid(signatureCounterValid)
      .clientExtensionOutputs(clientExtensionOutputs)
      .assertionExtensionOutputs(authenticatorExtensionOutputs.orNull)
      .build()
  )

  implicit val arbitraryRegistrationResult: Arbitrary[RegistrationResult] =
    Arbitrary(
      for {
        aaguid <- byteArray(16)
        attestationTrusted <- arbitrary[Boolean]
        attestationTrustPath <- generateAttestationCertificateChain
        attestationType <- arbitrary[AttestationType]
        authenticatorExtensionOutputs <-
          arbitrary[Option[AuthenticatorRegistrationExtensionOutputs]]
        clientExtensionOutputs <- arbitrary[ClientRegistrationExtensionOutputs]
        keyId <- arbitrary[PublicKeyCredentialDescriptor]
        publicKeyCose <- arbitrary[ByteArray]
        signatureCount <- arbitrary[Long]
      } yield RegistrationResult
        .builder()
        .keyId(keyId)
        .aaguid(aaguid)
        .attestationTrusted(attestationTrusted)
        .attestationType(attestationType)
        .publicKeyCose(publicKeyCose)
        .signatureCount(signatureCount)
        .clientExtensionOutputs(clientExtensionOutputs)
        .authenticatorExtensionOutputs(authenticatorExtensionOutputs.orNull)
        .attestationTrustPath(attestationTrustPath.asJava)
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

  def generateAttestationCertificateChain: Gen[List[X509Certificate]] =
    for {
      dummy <- Gen.nonEmptyListOf[Int](arbitrary[Int])
    } yield {
      if (dummy.length >= 2) {
        val tail = dummy.tail.init.foldLeft(
          List(TestAuthenticator.generateAttestationCaCertificate())
        )({
          case (chain, _) =>
            TestAuthenticator.generateAttestationCaCertificate(
              name = new X500Name(
                s"CN=Yubico WebAuthn unit tests intermediate CA ${chain.length}, O=Yubico, OU=Authenticator Attestation, C=SE"
              ),
              superCa = Some(chain.head),
            ) +: chain
        })
        (TestAuthenticator.generateAttestationCertificate(caCertAndKey =
          Some(tail.head)
        ) +: tail).map(_._1)
      } else {
        List(TestAuthenticator.generateAttestationCertificate()._1)
      }
    }

}
