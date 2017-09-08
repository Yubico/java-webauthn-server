package com.yubico.webauthn


import java.security.PublicKey
import java.util.Optional

import com.yubico.scala.util.JavaConverters._
import com.yubico.u2f.crypto.Crypto
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding
import com.yubico.webauthn.data.PublicKeyCredential
import com.yubico.webauthn.data.Base64UrlString
import com.yubico.webauthn.data.CollectedClientData
import com.yubico.webauthn.data.ArrayBuffer
import com.yubico.webauthn.data.AuthenticatorAssertionResponse

import scala.collection.JavaConverters._
import scala.util.Try

case class FinishAssertionSteps(
  request: PublicKeyCredentialRequestOptions,
  response: PublicKeyCredential[AuthenticatorAssertionResponse],
  callerTokenBindingId: Optional[Base64UrlString],
  origin: String,
  rpId: String,
  crypto: Crypto,
  credentialRepository: CredentialRepository,
) {

  sealed trait Step[A <: Step[_, _], B <: Step[_, _]] {
    protected def isFinished: Boolean = false
    protected def nextStep: B
    protected def result: Option[Boolean] = None
    protected def validate(): Unit

    private[webauthn] def next: Try[B] = validations map { _ => nextStep }
    private[webauthn] def prev: A
    private[webauthn] def validations: Try[Unit] = Try { validate() }

    def run: Try[Boolean] =
      if (isFinished) Try(result.get)
      else next flatMap { _.run }
  }

  private[webauthn] def begin: Step1 = Step1()
  def run: Try[Boolean] = begin.run

  case class Step1 private () extends Step[Step1, Step2] {
    override def prev = this
    override def nextStep = Step2(this)
    override def validate() = assert(_pubkey.isPresent, "Unknown credential ID.")

    private lazy val _pubkey: Optional[PublicKey] = (
      credentialRepository.lookup(response.id).asScala
        orElse credentialRepository.lookup(response.rawId).asScala
      ).asJava
    def pubkey: PublicKey = _pubkey.get
  }

  case class Step2 private (override val prev: Step1) extends Step[Step1, Step3] {
    override def validate() = {
      assert(response.response.clientData != null, "Missing client data.")
      assert(response.response.authenticatorData != null, "Missing authenticator data.")
      assert(response.response.signature != null, "Missing signature.")
    }
    override def nextStep = Step3(this)
  }

  case class Step3 private (override val prev: Step2) extends Step[Step2, Step4] {
    override def validate(): Unit = {
      assert(clientData != null, "Missing client data.")
    }
    override def nextStep = Step4(this)
    def clientData: CollectedClientData = response.response.collectedClientData
  }

  case class Step4 private (override val prev: Step3) extends Step[Step3, Step5] {
    override def validate() {
      assert(
        U2fB64Encoding.decode(response.response.collectedClientData.challenge).toVector == request.challenge,
        "Incorrect challenge."
      )
    }
    def nextStep = Step5(this)
  }

  case class Step5 private (override val prev: Step4) extends Step[Step4, Step6] {
    override def validate() {
      assert(
        response.response.collectedClientData.origin == origin,
        "Incorrect origin."
      )
    }
    override def nextStep = Step6(this)
  }

  case class Step6 private (override val prev: Step5) extends Step[Step5, Step7] {
    override def validate() {
      (callerTokenBindingId.asScala, response.response.collectedClientData.tokenBindingId.asScala) match {
        case (None, None) =>
        case (_, None) => throw new AssertionError("Token binding ID set by caller but not in attestation message.")
        case (None, _) => throw new AssertionError("Token binding ID set in attestation message but not by caller.")
        case (Some(callerToken), Some(responseToken)) =>
          assert(callerToken == responseToken, "Incorrect token binding ID.")
      }
    }
    override def nextStep = Step7(this)

    def clientDataJsonHash: ArrayBuffer = crypto.hash(response.response.clientDataJSON.toArray).toVector
  }
  case class Step7 private (override val prev: Step6) extends Step[Step6, Step8] {
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
    override def nextStep = Step8(this)
  }

  case class Step8 private (override val prev: Step7) extends Step[Step7, Step9] {
    override def validate() {
      assert(
        response.response.parsedAuthenticatorData.rpIdHash == crypto.hash(rpId).toVector,
        "Wrong RP ID hash."
      )
    }
    override def nextStep = Step9(this)
  }

  case class Step9 private (override val prev: Step8) extends Step[Step8, Step10] {
    override def validate(): Unit = {
      val hashAlgorithm: String = response.response.collectedClientData.hashAlgorithm.toLowerCase
      assert(
        supportedHashAlgorithms map { _.toLowerCase } contains hashAlgorithm,
        s"Forbidden hash algorithm: ${hashAlgorithm}"
      )
    }
    override def nextStep = Step10(this)

    def clientDataJsonHash: ArrayBuffer = crypto.hash(response.response.clientDataJSON.toArray).toVector
    val supportedHashAlgorithms: List[String] = List("SHA-256")
  }

  case class Step10 (override val prev: Step9) extends Step[Step9, Finished] {
    override def validate() {
      assert(
        Try(
          crypto.checkSignature(
            prev.prev.prev.prev.prev.prev.prev.prev.prev.pubkey,
            signedBytes.toArray,
            response.response.signature.toArray,
          )
        ).isSuccess,

        "Invalid assertion signature."
      )
    }
    override def nextStep = Finished(this)

    val signedBytes: ArrayBuffer = response.response.authenticatorData ++ prev.clientDataJsonHash
  }

  case class Finished private (override val prev: Step10) extends Step[Step10, Finished] {
    override def validate() { /* No-op */ }
    override def isFinished = true
    override def nextStep = this

    val success: Boolean = true
  }

}
