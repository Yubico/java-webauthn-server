package com.yubico.webauthn


import java.util.Optional

import com.yubico.scala.util.JavaConverters._
import com.yubico.u2f.crypto.Crypto
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding
import com.yubico.webauthn.data.PublicKeyCredential
import com.yubico.webauthn.data.Base64UrlString
import com.yubico.webauthn.data.CollectedClientData
import com.yubico.webauthn.data.ArrayBuffer
import com.yubico.webauthn.data.AuthenticatorAssertionResponse
import com.yubico.webauthn.data.Required
import com.yubico.webauthn.data.RegisteredCredential
import com.yubico.webauthn.data.AssertionResult
import com.yubico.webauthn.data.AssertionRequest
import com.yubico.webauthn.impl.TokenBindingValidator
import com.yubico.webauthn.impl.ExtensionsValidation
import com.yubico.webauthn.util.BinaryUtil
import org.slf4j.LoggerFactory
import org.slf4j.Logger

import scala.collection.JavaConverters._
import scala.util.Try
import scala.util.Failure
import scala.util.Success

object FinishAssertionSteps {
  val ClientDataType: String = "webauthn.get"
}

case class FinishAssertionSteps(
  request: AssertionRequest,
  response: PublicKeyCredential[AuthenticatorAssertionResponse],
  callerTokenBindingId: Optional[Base64UrlString],
  origins: java.util.List[String],
  rpId: String,
  crypto: Crypto,
  credentialRepository: CredentialRepository,
  allowMissingTokenBinding: Boolean = false,
  validateTypeAttribute: Boolean = true,
  validateSignatureCounter: Boolean = true,
  allowUnrequestedExtensions: Boolean = false
) {

  private val logger: Logger = LoggerFactory.getLogger(classOf[FinishAssertionSteps])

  sealed trait Step[A <: Step[_, _], B <: Step[_, _]] {
    protected def isFinished: Boolean = false
    protected def nextStep: B
    protected def result: Option[AssertionResult] = None
    protected def validate(): Unit
    protected def prevWarnings: List[String]
    protected def warnings: List[String] = Nil
    protected def allWarnings: List[String] = prevWarnings ++ warnings

    private[webauthn] def next: Try[B] = validations map { _ => nextStep }
    private[webauthn] def validations: Try[Unit] = Try { validate() }

    def run: Try[AssertionResult] =
      if (isFinished) Try(result.get)
      else next flatMap { _.run }
  }

  private[webauthn] def begin: Step0 = Step0()
  def run: Try[AssertionResult] = begin.run

  case class Step0 private[webauthn] () extends Step[Step0, Step1] {
    override def nextStep = Step1(username.get, userHandle.get, allWarnings)
    override def validate() = {
      assert(
        request.username.isPresent || response.response.userHandle.isPresent,
        "At least one of username and user handle must be given; none was."
      )
      assert(
        userHandle.isDefined,
        s"No user found for username: ${request.username.asScala}, userHandle: ${response.response.userHandleBase64}"
      )
      assert(
        username.isDefined,
        s"No user found for username: ${request.username.asScala}, userHandle: ${response.response.userHandleBase64}"
      )
    }
    override def prevWarnings = Nil

    private lazy val userHandle: Option[Base64UrlString] =
      Option(response.response.userHandleBase64)
        .orElse(credentialRepository.getUserHandleForUsername(request.username.get).asScala)

    private lazy val username: Option[String] =
      request.username.asScala
        .orElse(credentialRepository.getUsernameForUserHandle(U2fB64Encoding.encode(response.response.userHandle.get.toArray)).asScala)
  }

  case class Step1 private[webauthn] (username: String, userHandle: Base64UrlString, override val prevWarnings: List[String]) extends Step[Step0, Step2] {
    override def nextStep = Step2(username, userHandle, allWarnings)
    override def validate() = {
      request.publicKeyCredentialRequestOptions.allowCredentials.asScala match {
        case Some(allowed) =>
          assert(
            allowed.asScala exists { _.id == response.rawId },
            "Unrequested credential ID: " + response.id
          )
        case None =>
      }
    }
  }

  case class Step2 private[webauthn] (username: String, userHandle: Base64UrlString, override val prevWarnings: List[String]) extends Step[Step1, Step3] {
    override def nextStep = Step3(username, userHandle, allWarnings)
    override def validate() = {
      val registration = credentialRepository.lookup(response.id, userHandle).asScala
      assert(registration.isDefined, s"Unknown credential: ${response.id}")
      assert(
        BinaryUtil.toBase64(registration.get.userHandle) == userHandle,
        s"User handle ${userHandle} does not own credential ${response.id}"
      )
    }
  }

  case class Step3 private[webauthn] (username: String, userHandle: Base64UrlString, override val prevWarnings: List[String]) extends Step[Step2, Step4] {
    override def nextStep = Step4(username, userHandle, credential, allWarnings)
    override def validate() = {
      assert(_credential.isPresent, s"Unknown credential. Credential ID: ${response.id}, user handle: ${userHandle}")
    }

    private lazy val _credential: Optional[RegisteredCredential] =
      credentialRepository.lookup(response.id, userHandle)

    def credential: RegisteredCredential = _credential.get
  }

  case class Step4 private[webauthn] (username: String, userHandle: Base64UrlString, credential: RegisteredCredential, override val prevWarnings: List[String]) extends Step[Step3, Step5] {
    override def validate() = {
      assert(clientData != null, "Missing client data.")
      assert(authenticatorData != null, "Missing authenticator data.")
      assert(signature != null, "Missing signature.")
    }
    override def nextStep = Step5(username, userHandle, credential, allWarnings)

    def authenticatorData: ArrayBuffer = response.response.authenticatorData
    def clientData: ArrayBuffer = response.response.clientDataJSON
    def signature: ArrayBuffer = response.response.signature
  }

  case class Step5 private[webauthn] (username: String, userHandle: Base64UrlString, credential: RegisteredCredential, override val prevWarnings: List[String]) extends Step[Step4, Step6] {
    // Nothing to do
    override def validate(): Unit = {}
    override def nextStep = Step6(username, userHandle, credential,  allWarnings)
  }

  case class Step6 private[webauthn] (username: String, userHandle: Base64UrlString, credential: RegisteredCredential, override val prevWarnings: List[String]) extends Step[Step5, Step7] {
    override def validate(): Unit = {
      assert(clientData != null, "Missing client data.")
    }
    override def nextStep = Step7(username, userHandle, credential, clientData, allWarnings)
    def clientData: CollectedClientData = response.response.collectedClientData
  }

  case class Step7 private[webauthn] (username: String, userHandle: Base64UrlString, credential: RegisteredCredential, clientData: CollectedClientData, override val prevWarnings: List[String]) extends Step[Step6, Step8] {
    override def validate(): Unit = {
      try
        assert(
          clientData.`type` == FinishAssertionSteps.ClientDataType,
          s"""The "type" in the client data must be exactly "${FinishAssertionSteps.ClientDataType}", was: ${clientData.`type`}."""
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
    override def nextStep = Step8(username, userHandle, credential, allWarnings)
  }

  case class Step8 private[webauthn] (username: String, userHandle: Base64UrlString, credential: RegisteredCredential, override val prevWarnings: List[String]) extends Step[Step7, Step9] {
    override def validate() {
      assert(
        U2fB64Encoding.decode(response.response.collectedClientData.challenge).toVector == request.publicKeyCredentialRequestOptions.challenge,
        "Incorrect challenge."
      )
    }
    def nextStep = Step9(username, userHandle, credential, allWarnings)
  }

  case class Step9 private[webauthn] (username: String, userHandle: Base64UrlString, credential: RegisteredCredential, override val prevWarnings: List[String]) extends Step[Step8, Step10] {
    override def validate() {
      assert(
        origins contains response.response.collectedClientData.origin,
        "Incorrect origin: " + response.response.collectedClientData.origin
      )
    }
    override def nextStep = Step10(username, userHandle, credential, allWarnings)
  }

  case class Step10 private[webauthn] (username: String, userHandle: Base64UrlString, credential: RegisteredCredential, override val prevWarnings: List[String]) extends Step[Step9, Step11] {
    override def validate() = TokenBindingValidator.validate(response.response.collectedClientData.tokenBinding, callerTokenBindingId)
    override def nextStep = Step11(username, userHandle, credential, allWarnings)

    def clientDataJsonHash: ArrayBuffer = crypto.hash(response.response.clientDataJSON.toArray).toVector
  }

  case class Step11 private[webauthn] (username: String, userHandle: Base64UrlString, credential: RegisteredCredential, override val prevWarnings: List[String]) extends Step[Step10, Step12] {
    override def validate() {
      assert(
        response.response.parsedAuthenticatorData.rpIdHash == crypto.hash(rpId).toVector,
        "Wrong RP ID hash."
      )
    }
    override def nextStep = Step12(username, userHandle, credential, allWarnings)
  }

  case class Step12 private[webauthn] (username: String, userHandle: Base64UrlString, credential: RegisteredCredential, override val prevWarnings: List[String]) extends Step[Step11, Step13] {
    override def validate(): Unit = {
      if (request.publicKeyCredentialRequestOptions.userVerification == Required) {
        assert(response.response.parsedAuthenticatorData.flags.UV, "User Verification is required.")
      }
    }
    override def nextStep = Step13(username, userHandle, credential, allWarnings)
  }

  case class Step13 private[webauthn] (username: String, userHandle: Base64UrlString, credential: RegisteredCredential, override val prevWarnings: List[String]) extends Step[Step12, Step14] {
    override def validate(): Unit = {
      if (request.publicKeyCredentialRequestOptions.userVerification != Required) {
        assert(response.response.parsedAuthenticatorData.flags.UP, "User Presence is required.")
      }
    }
    override def nextStep = Step14(username, userHandle, credential, allWarnings)
  }

  case class Step14 private[webauthn] (username: String, userHandle: Base64UrlString, credential: RegisteredCredential, override val prevWarnings: List[String]) extends Step[Step13, Step15] {
    override def validate() {
      if (!allowUnrequestedExtensions) {
        ExtensionsValidation.validate(request.publicKeyCredentialRequestOptions.extensions.asScala, response)
      }
    }
    override def warnings = {
      Try(ExtensionsValidation.validate(request.publicKeyCredentialRequestOptions.extensions.asScala, response)) match {
        case Success(_) => Nil
        case Failure(e) => List(e.getMessage)
      }
    }
    override def nextStep = Step15(username, userHandle, credential, allWarnings)
  }

  case class Step15 private[webauthn] (username: String, userHandle: Base64UrlString, credential: RegisteredCredential, override val prevWarnings: List[String]) extends Step[Step14, Step16] {
    override def validate(): Unit = {
      assert(clientDataJsonHash != null, "Failed to compute hash of client data")
    }
    override def nextStep = Step16(username, userHandle, credential, clientDataJsonHash, allWarnings)

    def clientDataJsonHash: ArrayBuffer = crypto.hash(response.response.clientDataJSON.toArray).toVector
  }

  case class Step16 (username: String, userHandle: Base64UrlString, credential: RegisteredCredential, clientDataJsonHash: ArrayBuffer, override val prevWarnings: List[String]) extends Step[Step15, Step17] {
    override def validate() {
      assert(
        Try(
          crypto.checkSignature(
            credential.publicKey,
            signedBytes.toArray,
            response.response.signature.toArray
          )
        ).isSuccess,

        "Invalid assertion signature."
      )
    }
    override def nextStep = Step17(username, userHandle, allWarnings)

    val signedBytes: ArrayBuffer = response.response.authenticatorData ++ clientDataJsonHash
  }

  case class Step17 (username: String, userHandle: Base64UrlString, override val prevWarnings: List[String]) extends Step[Step16, Finished] {
    override def validate(): Unit = {
      if (validateSignatureCounter) {
        assert(
          signatureCounterValid,
          s"Signature counter must increase. Stored value: ${storedSignatureCountBefore}, received value: ${assertionSignatureCount}"
        )
      }
    }

    def signatureCounterValid: Boolean = (
      assertionSignatureCount == 0
        || assertionSignatureCount > storedSignatureCountBefore
    )

    override def nextStep = Finished(username, userHandle, assertionSignatureCount, signatureCounterValid, allWarnings)

    def storedSignatureCountBefore: Long =
      credentialRepository.lookup(response.id, userHandle).asScala
        .map(_.signatureCount)
        .getOrElse(0L)

    def assertionSignatureCount: Long = response.response.parsedAuthenticatorData.signatureCounter
  }

  case class Finished private[webauthn] (username: String, userHandle: Base64UrlString, assertionSignatureCount: Long, signatureCounterValid: Boolean, override val prevWarnings: List[String]) extends Step[Step17, Finished] {
    override def validate() { /* No-op */ }
    override def isFinished = true
    override def nextStep = this
    override def result: Option[AssertionResult] = Some(AssertionResult(
      credentialId = response.rawId,
      signatureCount = assertionSignatureCount,
      signatureCounterValid = signatureCounterValid,
      success = true,
      username = username,
      userHandle = userHandle,
      warnings = allWarnings
    ))

  }

}
