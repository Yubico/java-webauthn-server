package com.yubico.webauthn

import java.security.KeyPair
import java.util.Optional

import com.fasterxml.jackson.databind.node.JsonNodeFactory
import com.fasterxml.jackson.databind.node.ObjectNode
import com.yubico.internal.util.scala.JavaConverters._
import com.yubico.webauthn.data.CollectedClientData
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor
import com.yubico.webauthn.data.AuthenticatorAssertionResponse
import com.yubico.webauthn.data.PublicKeyCredential
import com.yubico.webauthn.data.RegisteredCredential
import com.yubico.webauthn.data.RelyingPartyIdentity
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions
import com.yubico.webauthn.data.ByteArray
import org.junit.runner.RunWith
import org.scalatest.FunSpec
import org.scalatest.Matchers
import org.scalatest.junit.JUnitRunner

import scala.collection.JavaConverters._
import scala.util.Success
import scala.util.Failure
import scala.util.Try


@RunWith(classOf[JUnitRunner])
class RelyingPartyUserIdentificationSpec  extends FunSpec with Matchers {

  private def jsonFactory: JsonNodeFactory = JsonNodeFactory.instance
  private val crypto: Crypto = new BouncyCastleCrypto()

  private object Defaults {

    val rpId = RelyingPartyIdentity.builder().name("Test party").id("localhost").build()

    // These values were generated using TestAuthenticator.makeCredentialExample(TestAuthenticator.createCredential())
    val authenticatorData: ByteArray = ByteArray.fromHex("49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630100000539")
    val clientDataJson: String = """{"challenge":"AAEBAgMFCA0VIjdZEGl5Yls","origin":"localhost","hashAlgorithm":"SHA-256","type":"webauthn.get","tokenBinding":{"status":"supported"}}"""
    val credentialId: ByteArray = ByteArray.fromBase64Url("aqFjEQkzH8I55SnmIyNM632MsPI_qZ60aGTSHZMwcKY")
    val credentialKey: KeyPair = TestAuthenticator.importEcKeypair(
      privateBytes = ByteArray.fromHex("308193020100301306072a8648ce3d020106082a8648ce3d0301070479307702010104206a88f478910df685bc0cfcc2077e64fb3a8ba770fb23fbbcd1f6572ce35cf360a00a06082a8648ce3d030107a14403420004d8020a2ec718c2c595bb890fcdaf9b81cc742118efdbb8812ac4a9dd5ace2990ec22a48faf1544df0fe5fe0e2e7a69720e63a83d7f46aa022f1323eaf7967762"),
      publicBytes = ByteArray.fromHex("3059301306072a8648ce3d020106082a8648ce3d03010703420004d8020a2ec718c2c595bb890fcdaf9b81cc742118efdbb8812ac4a9dd5ace2990ec22a48faf1544df0fe5fe0e2e7a69720e63a83d7f46aa022f1323eaf7967762")
    )
    val signature: ByteArray = ByteArray.fromHex("30450221008d478e4c24894d261c7fd3790363ba9687facf4dd1d59610933a2c292cffc3d902205069264c167833d239d6af4c7bf7326c4883fb8c3517a2c86318aa3060d8b441")

    // These values are not signed over
    val userHandle: ByteArray = ByteArray.fromHex("6d8972d9603ce4f3fa5d520ce6d024bf")

    // These values are defined by the attestationObject and clientDataJson above
    val clientDataJsonBytes: ByteArray = new ByteArray(clientDataJson.getBytes("UTF-8"))
    val clientData = new CollectedClientData(clientDataJsonBytes)
    val challenge: ByteArray = clientData.getChallenge
    val requestedExtensions: Option[ObjectNode] = None
    val clientExtensionResults: ObjectNode = jsonFactory.objectNode()

    val request = PublicKeyCredentialRequestOptions.builder()
      .challenge(challenge)
      .rpId(Some(rpId.getId).asJava)
      .build()

    val publicKeyCredential: PublicKeyCredential[AuthenticatorAssertionResponse] = new PublicKeyCredential(
      credentialId,
      new AuthenticatorAssertionResponse(
        authenticatorData,
        clientDataJsonBytes,
        signature,
        null
      ),
      jsonFactory.objectNode()
    )
    val username = "foo-user"

    def defaultResponse(
      userHandle: Option[ByteArray] = None
    ): AuthenticatorAssertionResponse = new AuthenticatorAssertionResponse(
      authenticatorData,
      clientDataJsonBytes,
      signature,
      userHandle.orNull
    )

    def defaultPublicKeyCredential(
      credentialId: ByteArray = Defaults.credentialId,
      response: Option[AuthenticatorAssertionResponse] = None,
      userHandle: Option[ByteArray] = None
    ): PublicKeyCredential[AuthenticatorAssertionResponse] =
      new PublicKeyCredential(
        credentialId,
        response getOrElse defaultResponse(userHandle = userHandle),
        jsonFactory.objectNode()
      )
  }

  describe("The assertion ceremony") {

    val rp = RelyingParty.builder()
      .allowUntrustedAttestation(false)
      .challengeGenerator(new ChallengeGenerator() { override def generateChallenge(): ByteArray = new ByteArray(Defaults.challenge.getBytes) })
      .origins(List(Defaults.rpId.getId).asJava)
      .preferredPubkeyParams(Nil.asJava)
      .rp(Defaults.rpId)
      .credentialRepository(new CredentialRepository {
        override def getCredentialIdsForUsername(username: String) =
          if (username == Defaults.username)
            Set(PublicKeyCredentialDescriptor.builder().id(Defaults.credentialId).build()).asJava
          else
            Set.empty.asJava

        override def lookup(credId: ByteArray, lookupUserHandle: ByteArray) =
          if (credId == Defaults.credentialId)
            Some(RegisteredCredential.builder()
              .credentialId(Defaults.credentialId)
              .userHandle(Defaults.userHandle)
              .publicKey(Defaults.credentialKey.getPublic)
              .signatureCount(0)
              .build()
            ).asJava
          else
            None.asJava

        override def lookupAll(credId: ByteArray) = ???
        override def getUserHandleForUsername(username: String): Optional[ByteArray] =
          if (username == Defaults.username)
            Some(Defaults.userHandle).asJava
          else
            None.asJava
        override def getUsernameForUserHandle(userHandle: ByteArray): Optional[String] =
          if (userHandle == Defaults.userHandle)
            Some(Defaults.username).asJava
          else
            None.asJava
      })
      .validateSignatureCounter(true)
      .build()

    it("succeeds for the default test case if a username was given.") {
      val request = rp.startAssertion(StartAssertionOptions.builder()
          .username(Optional.of(Defaults.username))
          .build())
      val result = Try(rp.finishAssertion(FinishAssertionOptions.builder()
          .request(request)
          .response(Defaults.publicKeyCredential)
          .build()
      ))

      result shouldBe a [Success[_]]
    }

    it("succeeds if username was not given but userHandle was returned.") {
      val request = rp.startAssertion(StartAssertionOptions.builder().build())

      val response: PublicKeyCredential[AuthenticatorAssertionResponse] = Defaults.defaultPublicKeyCredential(
        userHandle = Some(Defaults.userHandle)
      )

      val result = Try(rp.finishAssertion(FinishAssertionOptions.builder()
          .request(request)
          .response(response)
          .build()
      ))

      result shouldBe a [Success[_]]
    }

    it("fails for the default test case if no username was given and no userHandle returned.") {
      val request = rp.startAssertion(StartAssertionOptions.builder().build())
      val result = Try(rp.finishAssertion(FinishAssertionOptions.builder()
          .request(request)
          .response(Defaults.publicKeyCredential)
          .build()
      ))

      result shouldBe a [Failure[_]]
    }

  }

}
