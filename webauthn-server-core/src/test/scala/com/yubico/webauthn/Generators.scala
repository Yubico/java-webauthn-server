package com.yubico.webauthn

import com.yubico.scalacheck.gen.GenUtil.halfsized
import com.yubico.webauthn.data.AssertionExtensionInputs
import com.yubico.webauthn.data.AttestationType
import com.yubico.webauthn.data.AuthenticatorAssertionResponse
import com.yubico.webauthn.data.AuthenticatorAttestationResponse
import com.yubico.webauthn.data.ByteArray
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs
import com.yubico.webauthn.data.ClientRegistrationExtensionOutputs
import com.yubico.webauthn.data.Generators._
import com.yubico.webauthn.data.PublicKeyCredential
import com.yubico.webauthn.data.UserVerificationRequirement
import org.bouncycastle.asn1.x500.X500Name
import org.scalacheck.Arbitrary
import org.scalacheck.Arbitrary.arbitrary
import org.scalacheck.Gen

import java.security.cert.X509Certificate
import scala.jdk.CollectionConverters.SeqHasAsJava
import scala.jdk.OptionConverters.RichOption

object Generators {

  implicit val arbitraryAssertionResult: Arbitrary[AssertionResult] = Arbitrary(
    halfsized(
      for {
        credentialResponse <-
          arbitrary[PublicKeyCredential[
            AuthenticatorAssertionResponse,
            ClientAssertionExtensionOutputs,
          ]]
        credential <- arbitrary[RegisteredCredential]
        signatureCounterValid <- arbitrary[Boolean]
        success <- arbitrary[Boolean]
        username <- arbitrary[String]
      } yield new AssertionResult(
        success,
        credentialResponse,
        credential,
        username,
        signatureCounterValid,
      )
    )
  )

  implicit val arbitraryRegistrationResult: Arbitrary[RegistrationResult] =
    Arbitrary(
      halfsized(
        for {
          credential <-
            arbitrary[PublicKeyCredential[
              AuthenticatorAttestationResponse,
              ClientRegistrationExtensionOutputs,
            ]]
          attestationTrusted <- arbitrary[Boolean]
          attestationTrustPath <- generateAttestationCertificateChain
          attestationType <- arbitrary[AttestationType]
        } yield new RegistrationResult(
          credential,
          attestationTrusted,
          attestationType,
          Some(attestationTrustPath.asJava).toJava,
        )
      )
    )

  implicit val arbitraryRegisteredCredential: Arbitrary[RegisteredCredential] =
    Arbitrary(
      halfsized(
        for {
          credentialId <- arbitrary[ByteArray]
          userHandle <- arbitrary[ByteArray]
          publicKeyCose <- arbitrary[ByteArray]
          signatureCount <- arbitrary[Int]
          backupFlags <- Gen.option(arbitraryBackupFlags.arbitrary)
        } yield {
          val b = RegisteredCredential
            .builder()
            .credentialId(credentialId)
            .userHandle(userHandle)
            .publicKeyCose(publicKeyCose)
            .signatureCount(signatureCount)
          backupFlags.foreach({
            case ((be, bs)) =>
              b.backupEligible(be)
              b.backupState(bs)
          })
          b.build()
        }
      )
    )

  implicit val arbitraryStartAssertionOptions
      : Arbitrary[StartAssertionOptions] = Arbitrary(
    halfsized(
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
