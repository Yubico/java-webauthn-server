package com.yubico.webauthn

import java.security.cert.X509Certificate
import java.util.Optional

import com.yubico.scala.util.JavaConverters._
import com.yubico.u2f.attestation.MetadataService
import com.yubico.u2f.attestation.Attestation
import com.yubico.u2f.crypto.Crypto
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions
import com.yubico.webauthn.data.PublicKeyCredential
import com.yubico.webauthn.data.AuthenticatorAttestationResponse
import com.yubico.webauthn.data.Base64UrlString
import com.yubico.webauthn.data.CollectedClientData
import com.yubico.webauthn.data.PublicKeyCredentialType
import com.yubico.webauthn.data.AttestationObject
import com.yubico.webauthn.data.ArrayBuffer
import com.yubico.webauthn.data.AttestationType
import com.yubico.webauthn.data.Basic
import com.yubico.webauthn.data.SelfAttestation
import com.yubico.webauthn.data.Required
import com.yubico.webauthn.data.Preferred
import com.yubico.webauthn.data.NoneAttestation
import com.yubico.webauthn.data.RegistrationResult
import com.yubico.webauthn.impl.FidoU2fAttestationStatementVerifier
import com.yubico.webauthn.impl.KnownX509TrustAnchorsTrustResolver
import com.yubico.webauthn.impl.PackedAttestationStatementVerifier
import com.yubico.webauthn.impl.X5cAttestationStatementVerifier
import com.yubico.webauthn.impl.NoneAttestationStatementVerifier
import com.yubico.webauthn.impl.TokenBindingValidator
import com.yubico.webauthn.impl.ExtensionsValidation
import org.slf4j.LoggerFactory
import org.slf4j.Logger

import scala.util.Try
import scala.util.Success
import scala.util.Failure

sealed trait Step[A <: Step[_]] {
  protected def isFinished: Boolean = false
  protected def nextStep: A
  protected def result: Option[RegistrationResult] = None
  protected def validate(): Unit
  protected def warnings: List[String] = Nil

  private[webauthn] def next: Try[A] = validations map { _ => nextStep }
  private[webauthn] def validations: Try[Unit] = Try { validate() }

  def run: Try[RegistrationResult] =
    if (isFinished) Try(result.get)
    else next flatMap { _.run }
}

object FinishRegistrationSteps {
  val ClientDataType: String = "webauthn.create"
}

case class FinishRegistrationSteps(
  request: PublicKeyCredentialCreationOptions,
  response: PublicKeyCredential[AuthenticatorAttestationResponse],
  callerTokenBindingId: Optional[Base64UrlString],
  origins: java.util.List[String],
  rpId: String,
  crypto: Crypto,
  allowUnrequestedExtensions: Boolean = false,
  allowUntrustedAttestation: Boolean,
  metadataService: Optional[MetadataService],
  allowMissingTokenBinding: Boolean = false,
  validateTypeAttribute: Boolean = true,
  credentialRepository: CredentialRepository
) {
  private val logger: Logger = LoggerFactory.getLogger(classOf[FinishRegistrationSteps])

  private[webauthn] def begin: Step1 = Step1()
  def run: Try[RegistrationResult] = begin.run

  case class Step1 private[webauthn] () extends Step[Step2] {
    override def validate() = {}
    override def nextStep = Step2()
  }

  case class Step2 private[webauthn] () extends Step[Step3] {
    override def validate() = assert(clientData != null, "Client data must not be null.")
    override def nextStep = Step3(clientData)
    def clientData: CollectedClientData = response.response.collectedClientData
  }

  case class Step3 private[webauthn] (clientData: CollectedClientData) extends Step[Step4] {
    override def validate() = {
      try
        assert(
          clientData.`type` == FinishRegistrationSteps.ClientDataType,
          s"""The "type" in the client data must be exactly "${FinishRegistrationSteps.ClientDataType}", was: ${clientData.`type`}"""
        )
      catch {
        case e: AssertionError =>
          if (validateTypeAttribute)
            throw e
          else
            logger.warn(e.getMessage)

        case e: NullPointerException =>
          if (validateTypeAttribute)
            throw e
          else
            logger.warn("""Missing "type" attribute in client data.""")
      }
    }
    override def nextStep = Step4()
  }

  case class Step4 private[webauthn] () extends Step[Step5] {
    override def validate() {
      assert(
        U2fB64Encoding.decode(response.response.collectedClientData.challenge).toVector == request.challenge,
        "Incorrect challenge."
      )
    }
    override def nextStep = Step5()
  }

  case class Step5 private[webauthn] () extends Step[Step6] {
    override def validate() {
      assert(
        origins contains response.response.collectedClientData.origin,
        "Incorrect origin: " + response.response.collectedClientData.origin
      )
    }
    override def nextStep = Step6()
  }

  case class Step6 private[webauthn] () extends Step[Step7] {
    override def validate() = {
      TokenBindingValidator.validate(response.response.collectedClientData.tokenBinding, callerTokenBindingId)
    }
    def nextStep = Step7()
  }

  case class Step7 private[webauthn] () extends Step[Step8] {

    override def validate() {
      assert(clientDataJsonHash != null, "Failed to compute hash of client data")
    }
    override def nextStep = Step8(clientDataJsonHash)

    def clientDataJsonHash: ArrayBuffer = crypto.hash(response.response.clientDataJSON.toArray).toVector
  }
  case class Step8 private[webauthn] (clientDataJsonHash: ArrayBuffer) extends Step[Step9] {
    override def validate() {
      assert(attestation != null, "Malformed attestation object.")
    }
    override def nextStep = Step9(clientDataJsonHash, attestation)

    def attestation: AttestationObject = response.response.attestation
  }

  case class Step9 private[webauthn] (clientDataJsonHash: ArrayBuffer, attestation: AttestationObject) extends Step[Step10] {
    override def validate() {
      assert(
        response.response.attestation.authenticatorData.rpIdHash == crypto.hash(rpId).toVector,
        "Wrong RP ID hash."
      )
    }
    override def nextStep = Step10(clientDataJsonHash, attestation)
  }

  case class Step10 private[webauthn] (clientDataJsonHash: ArrayBuffer, attestation: AttestationObject) extends Step[Step11] {
    override def validate(): Unit = {
      if (request.authenticatorSelection.asScala.map(_.userVerification).getOrElse(Preferred) == Required) {
        assert(response.response.parsedAuthenticatorData.flags.UV, "User Verification is required.")
      }
    }
    override def nextStep = Step11(clientDataJsonHash, attestation)
  }

  case class Step11 private[webauthn] (clientDataJsonHash: ArrayBuffer, attestation: AttestationObject) extends Step[Step12] {
    override def validate(): Unit = {
      if (request.authenticatorSelection.asScala.map(_.userVerification).getOrElse(Preferred) != Required) {
        assert(response.response.parsedAuthenticatorData.flags.UP, "User Presence is required.")
      }
    }
    override def nextStep = Step12(clientDataJsonHash, attestation)
  }

  case class Step12 private[webauthn] (clientDataJsonHash: ArrayBuffer, attestation: AttestationObject) extends Step[Step13] {
    override def validate() {
      if (!allowUnrequestedExtensions) {
        ExtensionsValidation.validate(request.extensions.asScala, response)
      }
    }
    override def warnings = {
      Try(ExtensionsValidation.validate(request.extensions.asScala, response)) match {
        case Success(_) => Nil
        case Failure(e) => List(e.getMessage)
      }
    }
    override def nextStep = Step13(clientDataJsonHash, attestation, warnings)
  }

  case class Step13 private[webauthn] (clientDataJsonHash: ArrayBuffer, attestation: AttestationObject, override val warnings: List[String]) extends Step[Step14] {
    override def validate(): Unit = {
      assert(formatSupported, s"Unsupported attestation statement format: ${format}")
    }
    override def nextStep = Step14(clientDataJsonHash, attestation, attestationStatementVerifier.get, warnings)

    def format: String = attestation.format
    def formatSupported: Boolean = attestationStatementVerifier.isDefined
    def attestationStatementVerifier: Option[AttestationStatementVerifier] = format match {
      case "fido-u2f" => Some(FidoU2fAttestationStatementVerifier)
      case "none" => Some(NoneAttestationStatementVerifier)
      case "packed" => Some(PackedAttestationStatementVerifier)
      case _ => None
    }
  }

  case class Step14 (clientDataJsonHash: ArrayBuffer, attestation: AttestationObject, attestationStatementVerifier: AttestationStatementVerifier, override val warnings: List[String]) extends Step[Step15] {
    override def validate() {
      assert(
        attestationStatementVerifier.verifyAttestationSignature(attestation, clientDataJsonHash),
        "Invalid attestation signature."
      )
    }
    override def nextStep = Step15(
      attestation = attestation,
      attestationType = attestationType,
      attestationStatementVerifier = attestationStatementVerifier,
      warnings = warnings
    )

    def attestationType: AttestationType = attestationStatementVerifier.getAttestationType(attestation)
    def attestationTrustPath: Option[List[X509Certificate]] =
      attestationStatementVerifier match {
        case x5c: X5cAttestationStatementVerifier => x5c.getAttestationTrustPath(attestation)
        case _ => None
      }
  }

  case class Step15 private[webauthn] (
    private val attestation: AttestationObject,
    private val attestationType: AttestationType,
    private val attestationStatementVerifier: AttestationStatementVerifier,
    override val warnings: List[String]
  ) extends Step[Step16] {
    override def validate() {
      assert(attestationType == SelfAttestation || attestationType == NoneAttestation || trustResolver.isPresent, "Failed to obtain attestation trust anchors.")
    }
    override def nextStep = Step16(
      attestation = attestation,
      attestationType = attestationType,
      trustResolver = trustResolver,
      warnings = warnings
    )

    def trustResolver: Optional[AttestationTrustResolver] = (attestationType match {
      case SelfAttestation => None
      case Basic =>
        attestation.format match {
          case "fido-u2f"|"packed" => Try(new KnownX509TrustAnchorsTrustResolver(metadataService.get)).toOption
        }
      case NoneAttestation => None
      case _ => ???
    }).asJava
  }

  case class Step16 private[webauthn] (
    attestation: AttestationObject,
    attestationType: AttestationType,
    trustResolver: Optional[AttestationTrustResolver],
    override val warnings: List[String]
  ) extends Step[Step17] {
    override def validate() {
      attestationType match {
        case SelfAttestation =>
          assert(allowUntrustedAttestation, "Self attestation is not allowed.")

        case Basic =>
          assert(allowUntrustedAttestation || attestationTrusted, "Failed to derive trust for attestation key.")

        case NoneAttestation =>
          assert(allowUntrustedAttestation, "No attestation is not allowed.")

        case _ => ???
      }
    }
    override def nextStep = Step17(
      attestationTrusted = attestationTrusted,
      attestationType = attestationType,
      attestationMetadata = attestationMetadata,
      warnings = warnings
    )

    def attestationTrusted: Boolean = {
      attestationType match {
        case SelfAttestation | NoneAttestation => allowUntrustedAttestation
        case Basic => attestationMetadata.asScala exists { _.isTrusted }
        case _ => ???
      }
    }
    def attestationMetadata: Optional[Attestation] = trustResolver.asScala.flatMap(_.resolveTrustAnchor(attestation).asScala).asJava
  }

  case class Step17 private[webauthn] (
    attestationMetadata: Optional[Attestation],
    attestationTrusted: Boolean,
    attestationType: AttestationType,
    override val warnings: List[String]
  ) extends Step[Step18] {
    override def validate(): Unit = {
      assert(credentialRepository.lookupAll(response.id).isEmpty, s"Credential ID is already registered: ${response.id}")
    }
    override def nextStep = Step18(
      attestationTrusted = attestationTrusted,
      attestationType = attestationType,
      attestationMetadata = attestationMetadata,
      warnings = warnings
    )
  }

  case class Step18 private[webauthn] (
    attestationMetadata: Optional[Attestation],
    attestationTrusted: Boolean,
    attestationType: AttestationType,
    override val warnings: List[String]
  ) extends Step[Step19] {
    override def validate() {}
    override def nextStep = Step19(
      attestationTrusted = attestationTrusted,
      attestationType = attestationType,
      attestationMetadata = attestationMetadata,
      warnings = warnings
    )
  }

  case class Step19 private[webauthn] (
    attestationMetadata: Optional[Attestation],
    attestationTrusted: Boolean,
    attestationType: AttestationType,
    override val warnings: List[String]
  ) extends Step[Finished] {
    override def validate() {}
    override def nextStep = Finished(
      attestationTrusted = attestationTrusted,
      attestationType = attestationType,
      attestationMetadata = attestationMetadata,
      warnings = warnings
    )
  }

  case class Finished private[webauthn] (
    attestationMetadata: Optional[Attestation],
    attestationTrusted: Boolean,
    attestationType: AttestationType,
    override val warnings: List[String]
  ) extends Step[Finished] {
    override def validate() { /* No-op */ }
    override def isFinished = true
    override def nextStep = this

    override def result: Option[RegistrationResult] = Some(RegistrationResult(
      keyId = keyId,
      attestationTrusted = attestationTrusted,
      attestationType = attestationType,
      attestationMetadata = attestationMetadata,
      publicKeyCose = response.response.attestation.authenticatorData.attestationData.get.credentialPublicKey.toArray,
      warnings = warnings
    ))

    def keyId: PublicKeyCredentialDescriptor = PublicKeyCredentialDescriptor(
      `type` = PublicKeyCredentialType(response.`type`).get,
      id = response.rawId
    )
  }

}
