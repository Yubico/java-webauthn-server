package com.yubico.webauthn

import java.security.cert.X509Certificate
import java.util.Optional

import com.fasterxml.jackson.databind.JsonNode
import com.yubico.scala.util.JavaConverters._
import com.yubico.u2f.crypto.ChallengeGenerator
import com.yubico.u2f.crypto.BouncyCastleCrypto
import com.yubico.u2f.crypto.Crypto
import com.yubico.u2f.data.messages.key.RawRegisterResponse
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding
import com.yubico.u2f.data.messages.key.util.CertificateParser
import com.yubico.webauthn.data.MakePublicKeyCredentialOptions
import com.yubico.webauthn.data.UserIdentity
import com.yubico.webauthn.data.RelyingPartyIdentity
import com.yubico.webauthn.data.PublicKeyCredentialParameters
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria
import com.yubico.webauthn.data.AuthenticationExtensions
import com.yubico.webauthn.data.PublicKeyCredential
import com.yubico.webauthn.data.AuthenticatorAttestationResponse
import com.yubico.webauthn.data.AttestationObject
import com.yubico.webauthn.data.ArrayBuffer
import com.yubico.webauthn.data.PublicKeyCredentialType
import com.yubico.webauthn.data.Base64UrlString
import com.yubico.webauthn.data.CollectedClientData
import com.yubico.webauthn.data.AuthenticatorData

import scala.collection.JavaConverters._
import scala.util.Try
import scala.util.Failure

sealed trait Step[A <: Step[_]] {
  protected def isFinished: Boolean = false
  protected def nextStep: A
  protected def result: Option[PublicKeyCredentialDescriptor] = None
  protected def validate(): Unit = {}

  private[webauthn] def next: Try[A] = Try { validations } map { _ => nextStep }
  private[webauthn] def validations: Try[Unit] = Try { validate }

  def run: Try[PublicKeyCredentialDescriptor] =
    if (isFinished) Try(result.get)
    else next flatMap { _.run }
}

case class FinishRegistrationSteps(
  request: MakePublicKeyCredentialOptions,
  response: PublicKeyCredential[AuthenticatorAttestationResponse],
  callerTokenBindingId: Optional[Base64UrlString],
  origin: String,
  rp: RelyingPartyIdentity,
  crypto: Crypto,
  allowSelfAttestation: Boolean,
) {

  private[webauthn] def begin: Step1 = Step1()
  def run: Try[PublicKeyCredentialDescriptor] = begin.run

  case class Step1 private () extends Step[Step2] {
    override def validate() = assert(clientData != null, "Client data must not be null.")
    override def nextStep = Step2()
    def clientData: CollectedClientData = response.response.collectedClientData
  }

  case class Step2 private () extends Step[Step3] {
    override def validate() {
      assert(
        U2fB64Encoding.decode(response.response.collectedClientData.challenge).toVector == request.challenge,
        "Incorrect challenge."
      )
    }
    override def nextStep = Step3()
  }

  case class Step3 private () extends Step[Step4] {
    override def validate() {
      assert(
        response.response.collectedClientData.origin == origin,
        "Incorrect origin."
      )
    }
    override def nextStep = Step4()
  }

  case class Step4 private () extends Step[Step5] {
    override def validate() =
      (callerTokenBindingId.asScala, response.response.collectedClientData.tokenBindingId.asScala) match {
        case (None, None) =>
        case (_, None) => Failure(new AssertionError("Token binding ID set by caller but not in attestation message."))
        case (None, _) => Failure(throw new AssertionError("Token binding ID set in attestation message but not by caller."))
        case (Some(callerToken), Some(responseToken)) =>
          assert(callerToken == responseToken, "Incorrect token binding ID.")
      }
    def nextStep = Step5()
  }

  case class Step5 private () extends Step[Step6] {
    override def validate() {
      response.response.collectedClientData.clientExtensions.asScala foreach { extensions =>
        assert(
          request.extensions.isPresent,
          "Extensions were returned, but not requested."
        )

        assert(
          extensions.fieldNames.asScala.toSet subsetOf request.extensions.get.fieldNames.asScala.toSet,
          "Client extensions are not a subset of requested extensions."
        )
      }

      response.response.collectedClientData.authenticatorExtensions.asScala foreach { extensions =>
        assert(
          request.extensions.isPresent,
          "Extensions were returned, but not requested."
        )

        assert(
          extensions.fieldNames.asScala.toSet subsetOf request.extensions.get.fieldNames.asScala.toSet,
          "Authenticator extensions are not a subset of requested extensions."
        )
      }
    }
    override def nextStep = Step6()
  }

  case class Step6 private () extends Step[Step7] {
    val supportedHashAlgorithms: List[String] = List("SHA-256")

    override def validate() {
      val hashAlgorithm: String = response.response.collectedClientData.hashAlgorithm.toLowerCase
      assert(
        supportedHashAlgorithms map { _.toLowerCase } contains hashAlgorithm,
        s"Forbidden hash algorithm: ${hashAlgorithm}"
      )
    }
    override def nextStep = Step7(clientDataJsonHash)

    def clientDataJsonHash: ArrayBuffer = crypto.hash(response.response.clientDataJSON.toArray).toVector
  }
  case class Step7 private (clientDataJsonHash: ArrayBuffer) extends Step[Step8] {
    override def nextStep = Step8(clientDataJsonHash, attestation)

    def attestation: AttestationObject = response.response.attestation
  }

  case class Step8 private (clientDataJsonHash: ArrayBuffer, attestation: AttestationObject) extends Step[Step9] {
    override def validate() {
      assert(
        response.response.attestation.authenticatorData.rpIdHash == crypto.hash(rp.id).toVector,
        "Wrong RP ID hash."
      )
    }
    override def nextStep = Step9()
  }

  case class Step9 private () extends Step[Step10] { override def nextStep = Step10() }

  case class Step10 private () extends Step[Step11] {
    override def validate() {
      verifyAttestationSignature(response.response.attestation, response.response.clientDataJSON)
    }
    override def nextStep = Step11()

    private def verifyAttestationSignature(attestationObject: AttestationObject, buffer: data.ArrayBuffer): Unit = ???
  }

  case class Step11 private () extends Step[Step12] {
    override def validate() {
      verifyAttestationTrust()
    }
    override def nextStep = Step12()

    private def verifyAttestationTrust(): Unit = ???
  }

  case class Step12 private () extends Step[Step13] {
    override def nextStep = Step13(verifyAttestationTrustworthiness())

    def verifyAttestationTrustworthiness(): Boolean = ???
  }

  case class Step13 private (attestationSignatureTrusted: Boolean) extends Step[Step14] {
    override def nextStep = Step14(attestationSignatureTrusted)
  }

  case class Step14 private (attestationSignatureTrusted: Boolean) extends Step[Finished] {
    override def validate() {
      if (attestationSignatureTrusted) {
        registerNewCredential()
      } else if (allowSelfAttestation) {
        registerNewSelfAttestedCredential()
      } else {
        throw new AssertionError("Attestation signature is not trusted.")
      }
    }

    override def nextStep = Finished()

    def registerNewCredential(): Boolean = ???
    def registerNewSelfAttestedCredential(): Boolean = ???
  }

  case class Finished private () extends Step[Finished] {
    override def isFinished = true
    override def nextStep = this

    def keyId: PublicKeyCredentialDescriptor = PublicKeyCredentialDescriptor(
      `type` = PublicKeyCredentialType(response.`type`).get,
      id = response.rawId,
    )
  }

}

class RelyingParty (
  val rp: RelyingPartyIdentity,
  val challengeGenerator: ChallengeGenerator,
  val preferredPubkeyParams: Seq[PublicKeyCredentialParameters],
  val origin: String,
  val authenticatorRequirements: Optional[AuthenticatorSelectionCriteria] = None.asJava,
  val crypto: Crypto = new BouncyCastleCrypto,
  val allowSelfAttestation: Boolean = false,
) {

  def startRegistration(
    user: UserIdentity,
    excludeCredentials: Optional[Seq[PublicKeyCredentialDescriptor]] = None.asJava,
    extensions: Optional[AuthenticationExtensions] = None.asJava,
  ): MakePublicKeyCredentialOptions =
    MakePublicKeyCredentialOptions(
      rp = rp,
      user = user,
      challenge = challengeGenerator.generateChallenge().toVector,
      pubKeyCredParams = preferredPubkeyParams,
      excludeCredentials = excludeCredentials,
      authenticatorSelection = authenticatorRequirements,
      extensions = extensions
    )

  def finishRegistration(
    request: MakePublicKeyCredentialOptions,
    response: PublicKeyCredential[AuthenticatorAttestationResponse],
    callerTokenBindingId: Optional[Base64UrlString] = None.asJava,
  ): Try[PublicKeyCredentialDescriptor] =
    _finishRegistration(request, response, callerTokenBindingId).run

  private[webauthn] def _finishRegistration(
    request: MakePublicKeyCredentialOptions,
    response: PublicKeyCredential[AuthenticatorAttestationResponse],
    callerTokenBindingId: Optional[Base64UrlString] = None.asJava,
  ): FinishRegistrationSteps =
    FinishRegistrationSteps(
      request = request,
      response = response,
      callerTokenBindingId = callerTokenBindingId,
      origin = origin,
      rp = rp,
      crypto = crypto,
      allowSelfAttestation = allowSelfAttestation,
    )

  private def verifyAttestationSignature(
    attestationObject: AttestationObject,
    clientDataJsonBytes: ArrayBuffer,
  ): Try[Boolean] = {

    // val rpIdHash: ArrayBuffer = attestationObject.authenticatorData.rpIdHash
    // val credentialIdBytes: ArrayBuffer = attestationObject.authenticatorData.attestationData.get.credentialId
    // val credentialPublicKey: JsonNode = attestationObject.authenticatorData.attestationData.get.credentialPublicKey

    attestationObject.format match {
      case "fido-u2f" =>
        verifyU2fAttestationSignature(
          attestationObject,
          clientDataJsonBytes,
        )

      case other =>
        Failure(new UnsupportedOperationException(s"Unknown attestation statement format: ${other}"))
    }
  }

  private def verifyU2fAttestationSignature(
    attestationObject: AttestationObject,
    clientDataJsonBytes: ArrayBuffer,
  ): Try[Boolean] = {

    val attestationStatement = attestationObject.attestationStatement
    val certificates = attestationStatement.get("x5c")
    assert(certificates.isArray, """Property "x5c" of a "fido-u2f" attestation statement must be an array.""")

    val attestationCert: X509Certificate = CertificateParser.parseDer(certificates.get(0).binaryValue())
    println(s"Attestation cert: ${attestationCert}")
    println(s"Attestation cert public key: ${attestationCert.getPublicKey} ${U2fB64Encoding.encode(attestationCert.getPublicKey.getEncoded)}")

    Try {
      new RawRegisterResponse(
        ecKeyToBytes(attestationObject.authenticatorData.attestationData.get.credentialPublicKey),
        attestationObject.authenticatorData.attestationData.get.credentialId.toArray,
        attestationCert,
        attestationStatement.get("sig").binaryValue(),
      ).checkSignature(origin, U2fB64Encoding.encode(clientDataJsonBytes.toArray))

      true
    }
  }

  private def ecKeyToBytes(key: JsonNode): Array[Byte] = {
    val x = key.get("x").binaryValue()
    val y = key.get("y").binaryValue()
    assert(x.length == 32 && y.length == 32, s"EC key coordinates must be 32 bytes long, was: ({$x.length}, ${y.length})")

    (Vector(0x04: Byte) ++ x ++ y).toArray
  }

}
