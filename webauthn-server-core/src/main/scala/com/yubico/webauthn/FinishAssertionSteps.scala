package com.yubico.webauthn


import java.util.Optional
import java.util.function.Supplier

import com.yubico.scala.util.JavaConverters._
import com.yubico.u2f.crypto.Crypto
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding
import com.yubico.webauthn.data.PublicKeyCredential
import com.yubico.webauthn.data.Base64UrlString
import com.yubico.webauthn.data.CollectedClientData
import com.yubico.webauthn.data.ArrayBuffer
import com.yubico.webauthn.data.AuthenticatorAssertionResponse
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions
import com.yubico.webauthn.data.Required
import com.yubico.webauthn.data.RegisteredCredential
import com.yubico.webauthn.data.AssertionResult
import com.yubico.webauthn.impl.TokenBindingValidator
import com.yubico.webauthn.impl.ExtensionsValidation
import com.yubico.webauthn.util.BinaryUtil
import org.slf4j.LoggerFactory
import org.slf4j.Logger

import scala.collection.JavaConverters._
import scala.util.Try

object FinishAssertionSteps {
  val ClientDataType: String = "webauthn.get"
}

case class FinishAssertionSteps(
  request: PublicKeyCredentialRequestOptions,
  response: PublicKeyCredential[AuthenticatorAssertionResponse],
  callerTokenBindingId: Optional[Base64UrlString],
  origins: java.util.List[String],
  rpId: String,
  crypto: Crypto,
  credentialRepository: CredentialRepository,
  getUserHandle: Supplier[Base64UrlString],
  allowMissingTokenBinding: Boolean = false,
  validateTypeAttribute: Boolean = true,
  validateSignatureCounter: Boolean = true
) {

  private val logger: Logger = LoggerFactory.getLogger(classOf[FinishAssertionSteps])

  private val userHandle: Base64UrlString =
    Option(response.response.userHandleBase64) getOrElse getUserHandle.get()

  sealed trait Step[A <: Step[_, _], B <: Step[_, _]] {
    protected def isFinished: Boolean = false
    protected def nextStep: B
    protected def result: Option[AssertionResult] = None
    protected def validate(): Unit

    private[webauthn] def next: Try[B] = validations map { _ => nextStep }
    private[webauthn] def prev: A
    private[webauthn] def validations: Try[Unit] = Try { validate() }

    def run: Try[AssertionResult] =
      if (isFinished) Try(result.get)
      else next flatMap { _.run }
  }

  private[webauthn] def begin: Step1 = Step1()
  def run: Try[AssertionResult] = begin.run

  case class Step1 private[webauthn] () extends Step[Step1, Step2] {
    override def prev = this
    override def nextStep = Step2(this)
    override def validate() = {
      request.allowCredentials.asScala match {
        case Some(allowed) =>
          assert(
            allowed.asScala exists { _.id == response.rawId },
            "Unrequested credential ID: " + response.id
          )
        case None =>
      }
    }
  }

  case class Step2 private[webauthn] (override val prev: Step1) extends Step[Step1, Step3] {
    override def nextStep = Step3(this)
    override def validate() = {
      val registration = credentialRepository.lookup(response.id, Some(userHandle).asJava).asScala
      assert(registration.isDefined, s"Unknown credential: ${response.id}")
      assert(
        BinaryUtil.toBase64(registration.get.userHandle) == userHandle,
        s"User handle ${userHandle} does not own credential ${response.id}"
      )
    }
  }

  case class Step3 private[webauthn] (override val prev: Step2) extends Step[Step2, Step4] {
    override def nextStep = Step4(this)
    override def validate() = {
      assert(_credential.isPresent, s"Unknown credential. Credential ID: ${response.id}, user handle: ${userHandle}")
    }

    private lazy val _credential: Optional[RegisteredCredential] =
      credentialRepository.lookup(response.id, Optional.of(userHandle))

    def credential: RegisteredCredential = _credential.get
  }

  case class Step4 private[webauthn] (override val prev: Step3) extends Step[Step3, Step5] {
    override def validate() = {
      assert(clientData != null, "Missing client data.")
      assert(authenticatorData != null, "Missing authenticator data.")
      assert(signature != null, "Missing signature.")
    }
    override def nextStep = Step5(this)

    def authenticatorData: ArrayBuffer = response.response.authenticatorData
    def clientData: ArrayBuffer = response.response.clientDataJSON
    def signature: ArrayBuffer = response.response.signature
  }

  case class Step5 private[webauthn] (override val prev: Step4) extends Step[Step4, Step6] {
    // Nothing to do
    override def validate(): Unit = {}
    override def nextStep = Step6(this)
  }

  case class Step6 private[webauthn] (override val prev: Step5) extends Step[Step5, Step7] {
    override def validate(): Unit = {
      assert(clientData != null, "Missing client data.")
    }
    override def nextStep = Step7(this)
    def clientData: CollectedClientData = response.response.collectedClientData
  }

  case class Step7 private[webauthn] (override val prev: Step6) extends Step[Step6, Step8] {
    override def validate(): Unit = {
      try
        assert(
          prev.clientData.`type` == FinishAssertionSteps.ClientDataType,
          s"""The "type" in the client data must be exactly "${FinishAssertionSteps.ClientDataType}", was: ${prev.clientData.`type`}."""
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
    override def nextStep = Step8(this)
  }

  case class Step8 private[webauthn] (override val prev: Step7) extends Step[Step7, Step9] {
    override def validate() {
      assert(
        U2fB64Encoding.decode(response.response.collectedClientData.challenge).toVector == request.challenge,
        "Incorrect challenge."
      )
    }
    def nextStep = Step9(this)
  }

  case class Step9 private[webauthn] (override val prev: Step8) extends Step[Step8, Step10] {
    override def validate() {
      assert(
        origins contains response.response.collectedClientData.origin,
        "Incorrect origin: " + response.response.collectedClientData.origin
      )
    }
    override def nextStep = Step10(this)
  }

  case class Step10 private[webauthn] (override val prev: Step9) extends Step[Step9, Step11] {
    override def validate() = TokenBindingValidator.validate(response.response.collectedClientData.tokenBinding, callerTokenBindingId)
    override def nextStep = Step11(this)

    def clientDataJsonHash: ArrayBuffer = crypto.hash(response.response.clientDataJSON.toArray).toVector
  }

  case class Step11 private[webauthn] (override val prev: Step10) extends Step[Step10, Step12] {
    override def validate() {
      assert(
        response.response.parsedAuthenticatorData.rpIdHash == crypto.hash(rpId).toVector,
        "Wrong RP ID hash."
      )
    }
    override def nextStep = Step12(this)
  }

  case class Step12 private[webauthn] (override val prev: Step11) extends Step[Step11, Step13] {
    override def validate(): Unit = {
      if (request.userVerification == Required) {
        assert(response.response.parsedAuthenticatorData.flags.UV, "User Verification is required.")
      }
    }
    override def nextStep = Step13(this)
  }

  case class Step13 private[webauthn] (override val prev: Step12) extends Step[Step12, Step14] {
    override def validate(): Unit = {
      if (request.userVerification != Required) {
        assert(response.response.parsedAuthenticatorData.flags.UP, "User Presence is required.")
      }
    }
    override def nextStep = Step14(this)
  }

  case class Step14 private[webauthn] (override val prev: Step13) extends Step[Step13, Step15] {
    override def validate() {
      ExtensionsValidation.validate(request.extensions.asScala, response)
    }
    override def nextStep = Step15(this)
  }

  case class Step15 private[webauthn] (override val prev: Step14) extends Step[Step14, Step16] {
    override def validate(): Unit = {
      assert(clientDataJsonHash != null, "Failed to compute hash of client data")
    }
    override def nextStep = Step16(this)

    def clientDataJsonHash: ArrayBuffer = crypto.hash(response.response.clientDataJSON.toArray).toVector
  }

  case class Step16 (override val prev: Step15) extends Step[Step15, Step17] {
    override def validate() {
      assert(
        Try(
          crypto.checkSignature(
            prev.prev.prev.prev.prev.prev.prev.prev.prev.prev.prev.prev.prev.credential.publicKey,
            signedBytes.toArray,
            response.response.signature.toArray
          )
        ).isSuccess,

        "Invalid assertion signature."
      )
    }
    override def nextStep = Step17(this)

    val signedBytes: ArrayBuffer = response.response.authenticatorData ++ prev.clientDataJsonHash
  }

  case class Step17 (override val prev: Step16) extends Step[Step16, Finished] {
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

    override def nextStep = Finished(this)

    def storedSignatureCountBefore: Long =
      credentialRepository.lookup(response.id, Optional.of(userHandle)).asScala
        .map(_.signatureCount)
        .getOrElse(0L)

    def assertionSignatureCount: Long = response.response.parsedAuthenticatorData.signatureCounter
  }

  case class Finished private[webauthn] (override val prev: Step17) extends Step[Step17, Finished] {
    override def validate() { /* No-op */ }
    override def isFinished = true
    override def nextStep = this
    override def result: Option[AssertionResult] = Some(AssertionResult(
      credentialId = response.rawId,
      signatureCount = prev.assertionSignatureCount,
      signatureCounterValid = prev.signatureCounterValid,
      success = true,
      userHandle = userHandle
    ))

  }

}
