package com.yubico.webauthn.impl

import java.security.MessageDigest
import java.security.KeyPair
import java.util.Optional

import com.fasterxml.jackson.core.JsonParseException
import com.fasterxml.jackson.databind.node.JsonNodeFactory
import com.fasterxml.jackson.databind.node.ObjectNode
import com.yubico.scala.util.JavaConverters._
import com.yubico.u2f.crypto.BouncyCastleCrypto
import com.yubico.u2f.crypto.Crypto
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding
import com.yubico.webauthn.RelyingParty
import com.yubico.webauthn.FinishAssertionSteps
import com.yubico.webauthn.CredentialRepository
import com.yubico.webauthn.data.ArrayBuffer
import com.yubico.webauthn.data.AuthenticationExtensionsClientInputs
import com.yubico.webauthn.data.CollectedClientData
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor
import com.yubico.webauthn.data.RelyingPartyIdentity
import com.yubico.webauthn.data.Base64UrlString
import com.yubico.webauthn.data.UserVerificationRequirement
import com.yubico.webauthn.data.AuthenticatorAssertionResponse
import com.yubico.webauthn.data.PublicKeyCredential
import com.yubico.webauthn.data.RegisteredCredential
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions
import com.yubico.webauthn.data.AssertionRequest
import com.yubico.webauthn.test.TestAuthenticator
import com.yubico.webauthn.util.BinaryUtil
import com.yubico.webauthn.util.WebAuthnCodecs
import org.junit.runner.RunWith
import org.scalacheck.Gen
import org.scalatest.FunSpec
import org.scalatest.Matchers
import org.scalatest.junit.JUnitRunner
import org.scalatest.prop.GeneratorDrivenPropertyChecks

import scala.collection.JavaConverters._
import scala.util.Failure
import scala.util.Success
import scala.util.Try


@RunWith(classOf[JUnitRunner])
class RelyingPartyAssertionSpec extends FunSpec with Matchers with GeneratorDrivenPropertyChecks {

  private def jsonFactory: JsonNodeFactory = JsonNodeFactory.instance
  private val crypto: Crypto = new BouncyCastleCrypto()

  private object Defaults {

    val rpId = RelyingPartyIdentity.builder().name("Test party").id("localhost").build()

    // These values were generated using TestAuthenticator.makeCredentialExample(TestAuthenticator.createCredential())
    val authenticatorData: ArrayBuffer = BinaryUtil.fromHex("49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630100000539").toVector
    val clientDataJson: String = """{"challenge":"AAEBAgMFCA0VIjdZEGl5Yls","origin":"localhost","hashAlgorithm":"SHA-256","type":"webauthn.get","tokenBinding":{"status":"supported"}}"""
    val credentialId: ArrayBuffer = U2fB64Encoding.decode("aqFjEQkzH8I55SnmIyNM632MsPI_qZ60aGTSHZMwcKY").toVector
    val credentialKey: KeyPair = TestAuthenticator.importEcKeypair(
      privateBytes = BinaryUtil.fromHex("308193020100301306072a8648ce3d020106082a8648ce3d0301070479307702010104206a88f478910df685bc0cfcc2077e64fb3a8ba770fb23fbbcd1f6572ce35cf360a00a06082a8648ce3d030107a14403420004d8020a2ec718c2c595bb890fcdaf9b81cc742118efdbb8812ac4a9dd5ace2990ec22a48faf1544df0fe5fe0e2e7a69720e63a83d7f46aa022f1323eaf7967762").toVector,
      publicBytes = BinaryUtil.fromHex("3059301306072a8648ce3d020106082a8648ce3d03010703420004d8020a2ec718c2c595bb890fcdaf9b81cc742118efdbb8812ac4a9dd5ace2990ec22a48faf1544df0fe5fe0e2e7a69720e63a83d7f46aa022f1323eaf7967762").toVector
    )
    val signature: ArrayBuffer = BinaryUtil.fromHex("30450221008d478e4c24894d261c7fd3790363ba9687facf4dd1d59610933a2c292cffc3d902205069264c167833d239d6af4c7bf7326c4883fb8c3517a2c86318aa3060d8b441").toVector

    // These values are not signed over
    val username: Base64UrlString = "foo-user"
    val userHandle: ArrayBuffer = BinaryUtil.fromHex("6d8972d9603ce4f3fa5d520ce6d024bf").toVector

    // These values are defined by the attestationObject and clientDataJson above
    val clientData = new CollectedClientData(WebAuthnCodecs.json.readTree(clientDataJson))
    val clientDataJsonBytes: ArrayBuffer = clientDataJson.getBytes("UTF-8").toVector
    val challenge: ArrayBuffer = clientData.getChallenge.toVector
    val requestedExtensions: Option[AuthenticationExtensionsClientInputs] = None
    val clientExtensionResults: AuthenticationExtensionsClientInputs = jsonFactory.objectNode()

  }

  private def getUserHandleIfDefault(username: String, userHandle: ArrayBuffer = Defaults.userHandle): Optional[Base64UrlString] =
    if (username == Defaults.username)
      Some(U2fB64Encoding.encode(userHandle.toArray)).asJava
    else
      ???

  def finishAssertion(
    allowCredentials: Option[java.util.List[PublicKeyCredentialDescriptor]] = Some(List(new PublicKeyCredentialDescriptor(Defaults.credentialId.toArray)).asJava),
    authenticatorData: ArrayBuffer = Defaults.authenticatorData,
    callerTokenBindingId: Option[String] = None,
    challenge: ArrayBuffer = Defaults.challenge,
    clientDataJson: String = Defaults.clientDataJson,
    clientExtensionResults: AuthenticationExtensionsClientInputs = Defaults.clientExtensionResults,
    credentialId: ArrayBuffer = Defaults.credentialId,
    credentialKey: KeyPair = Defaults.credentialKey,
    credentialRepository: Option[CredentialRepository] = None,
    origin: String = Defaults.rpId.getId,
    requestedExtensions: Option[AuthenticationExtensionsClientInputs] = Defaults.requestedExtensions,
    rpId: RelyingPartyIdentity = Defaults.rpId,
    signature: ArrayBuffer = Defaults.signature,
    userHandleForResponse: Option[ArrayBuffer] = None,
    userHandleForUser: ArrayBuffer = Defaults.userHandle,
    userVerificationRequirement: UserVerificationRequirement = UserVerificationRequirement.PREFERRED,
    validateSignatureCounter: Boolean = true
  ): FinishAssertionSteps = {
    val clientDataJsonBytes: ArrayBuffer = if (clientDataJson == null) null else clientDataJson.getBytes("UTF-8").toVector

    val request = AssertionRequest.builder()
      .requestId("")
      .username(Some(Defaults.username).asJava)
      .publicKeyCredentialRequestOptions(PublicKeyCredentialRequestOptions.builder()
        .rpId(Some(rpId.getId).asJava)
        .challenge(challenge.toArray)
        .allowCredentials(allowCredentials.asJava)
        .userVerification(userVerificationRequirement)
        .extensions(requestedExtensions.asJava)
        .build()
      )
      .build()

    val response = new PublicKeyCredential(
      U2fB64Encoding.encode(credentialId.toArray),
      new AuthenticatorAssertionResponse(
        if (authenticatorData == null) null else U2fB64Encoding.encode(authenticatorData.toArray),
        if (clientDataJsonBytes == null) null else U2fB64Encoding.encode(clientDataJsonBytes.toArray),
        if (signature == null) null else U2fB64Encoding.encode(signature.toArray),
        userHandleForResponse.map(uh => U2fB64Encoding.encode(uh.toArray)).orNull
      ),
      clientExtensionResults
    )

    new RelyingParty(
      allowUntrustedAttestation = false,
      challengeGenerator = null,
      origins = List(origin).asJava,
      preferredPubkeyParams = Nil.asJava,
      rp = rpId,
      credentialRepository = credentialRepository getOrElse new CredentialRepository {
        override def lookup(credId: Base64UrlString, lookupUserHandle: Base64UrlString) =
          (
            if (credId == U2fB64Encoding.encode(credentialId.toArray))
              Some(new RegisteredCredential(
                U2fB64Encoding.decode(credId),
                userHandleForUser.toArray,
                credentialKey.getPublic,
                0L
              ))
            else None
          ).asJava
        override def lookupAll(credId: Base64UrlString) = lookup(credId, null).asScala.toSet.asJava
        override def getCredentialIdsForUsername(username: String): java.util.List[PublicKeyCredentialDescriptor] = ???
        override def getUserHandleForUsername(username: String): Optional[Base64UrlString] = getUserHandleIfDefault(username, userHandle = userHandleForUser)
        override def getUsernameForUserHandle(userHandle: Base64UrlString): Optional[String] = ???
      },
      validateSignatureCounter = validateSignatureCounter
    )._finishAssertion(request, response, callerTokenBindingId.asJava)
  }

  case class StepWithValidations(a: { def validate(): Unit }) {
    def validations: Try[Unit] = Try(a.validate())
  }
  implicit def toStepWithValidationsMethod(s: { def validate(): Unit }) = StepWithValidations(s)

  describe("§7.2. Verifying an authentication assertion") {

    describe("When verifying a given PublicKeyCredential structure (credential) and an AuthenticationExtensionsClientOutputs structure clientExtensionResults, as part of an authentication ceremony, the Relying Party MUST proceed as follows:") {

      describe("1. If the allowCredentials option was given when this authentication ceremony was initiated, verify that credential.id identifies one of the public key credentials that were listed in allowCredentials.") {
        it("Fails if returned credential ID is a requested one.") {
          val steps = finishAssertion(
            allowCredentials = Some(List(new PublicKeyCredentialDescriptor(Array(3, 2, 1, 0))).asJava),
            credentialId = Vector(0, 1, 2, 3)
          )
          val step: steps.Step1 = steps.begin.next

          step.validations shouldBe a [Failure[_]]
          step.validations.failed.get shouldBe an [AssertionError]
          step.next shouldBe a [Failure[_]]
        }

        it("Succeeds if returned credential ID is a requested one.") {
          val steps = finishAssertion(
            allowCredentials = Some(List(
              new PublicKeyCredentialDescriptor(Array(0, 1, 2, 3)),
              new PublicKeyCredentialDescriptor(Array(4, 5, 6, 7))
            ).asJava),
            credentialId = Vector(4, 5, 6, 7)
          )
          val step: FinishAssertionSteps#Step1 = steps.begin.next

          step.validations shouldBe a [Success[_]]
          step.next shouldBe a [Success[_]]
        }

        it("Succeeds if returned no credential IDs were requested.") {
          val steps = finishAssertion(
            allowCredentials = None,
            credentialId = Vector(0, 1, 2, 3)
          )
          val step: FinishAssertionSteps#Step1 = steps.begin.next

          step.validations shouldBe a [Success[_]]
          step.next shouldBe a [Success[_]]
        }
      }

      describe("2. If credential.response.userHandle is present, verify that the user identified by this value is the owner of the public key credential identified by credential.id.") {
        val credentialRepository = Some(new CredentialRepository {
          override def lookup(id: Base64UrlString, uh: Base64UrlString) = Some(
            new RegisteredCredential(
              Array(0, 1, 2, 3),
              Array(4, 5, 6, 7),
              Defaults.credentialKey.getPublic,
              0L
            )
          ).asJava
          override def lookupAll(id: Base64UrlString) = ???
          override def getCredentialIdsForUsername(username: String): java.util.List[PublicKeyCredentialDescriptor] = ???
          override def getUserHandleForUsername(username: String): Optional[Base64UrlString] = getUserHandleIfDefault(username, userHandle = Vector(4, 5, 6, 7))
          override def getUsernameForUserHandle(userHandle: Base64UrlString): Optional[String] = ???
        })

        it("Fails if credential ID is not owned by the given user handle.") {
          val steps = finishAssertion(
            credentialRepository = credentialRepository,
            userHandleForUser = Vector(4, 5, 6, 7),
            userHandleForResponse = Some(Vector(8, 9, 10, 11))
          )
          val step: steps.Step2 = steps.begin.next.next

          step.validations shouldBe a [Failure[_]]
          step.validations.failed.get shouldBe an [AssertionError]
          step.next shouldBe a [Failure[_]]
        }

        it("Succeeds if credential ID is owned by the given user handle.") {
          val steps = finishAssertion(
            credentialRepository = credentialRepository,
            userHandleForUser = Vector(4, 5, 6, 7),
            userHandleForResponse = Some(Vector(4, 5, 6, 7))
          )
          val step: steps.Step2 = steps.begin.next.next

          step.validations shouldBe a [Success[_]]
          step.next shouldBe a [Success[_]]
        }
      }

      describe("3. Using credential’s id attribute (or the corresponding rawId, if base64url encoding is inappropriate for your use case), look up the corresponding credential public key.") {
        it("Fails if the credential ID is unknown.") {
          val steps = finishAssertion(
            credentialRepository = Some(new CredentialRepository {
              override def lookup(id: Base64UrlString, uh: Base64UrlString) = None.asJava
              override def lookupAll(id: Base64UrlString) = Set.empty.asJava
              override def getCredentialIdsForUsername(username: String): java.util.List[PublicKeyCredentialDescriptor] = ???
              override def getUserHandleForUsername(username: String): Optional[Base64UrlString] = ???
              override def getUsernameForUserHandle(userHandle: Base64UrlString): Optional[String] = ???
            })
          )
          val step: steps.Step3 = new steps.Step3(Defaults.username, U2fB64Encoding.encode(Defaults.userHandle.toArray), Nil.asJava)

          step.validations shouldBe a [Failure[_]]
          step.validations.failed.get shouldBe an [AssertionError]
          step.next shouldBe a [Failure[_]]
        }

        it("Succeeds if the credential ID is known.") {
          val steps = finishAssertion(credentialRepository = Some(new CredentialRepository {
            override def lookup(id: Base64UrlString, uh: Base64UrlString) = Some(
              new RegisteredCredential(
                U2fB64Encoding.decode(id),
                U2fB64Encoding.decode(uh),
                Defaults.credentialKey.getPublic,
                0L
              )
            ).asJava
            override def lookupAll(id: Base64UrlString) = ???
            override def getCredentialIdsForUsername(username: String): java.util.List[PublicKeyCredentialDescriptor] = ???
            override def getUserHandleForUsername(username: String): Optional[Base64UrlString] = getUserHandleIfDefault(username)
            override def getUsernameForUserHandle(userHandle: Base64UrlString): Optional[String] = ???
          }))
          val step: FinishAssertionSteps#Step3 = steps.begin.next.next.next

          step.validations shouldBe a [Success[_]]
          step.credential.publicKey should equal (Defaults.credentialKey.getPublic)
          step.next shouldBe a [Success[_]]
        }
      }

      describe("4. Let cData, aData and sig denote the value of credential’s response's clientDataJSON, authenticatorData, and signature respectively.") {
        it("Succeeds if all three are present.") {
          val steps = finishAssertion()
          val step: FinishAssertionSteps#Step4 = steps.begin.next.next.next.next

          step.validations shouldBe a [Success[_]]
          step.clientData should not be null
          step.authenticatorData should not be null
          step.signature should not be null
          step.next shouldBe a [Success[_]]
        }

        it("Fails if clientDataJSON is missing.") {
          a [NullPointerException] should be thrownBy finishAssertion(clientDataJson = null)
        }

        it("Fails if authenticatorData is missing.") {
          a [NullPointerException] should be thrownBy finishAssertion(authenticatorData = null)
        }

        it("Fails if signature is missing.") {
          a [NullPointerException] should be thrownBy finishAssertion(signature = null)
        }
      }

      describe("5. Let JSONtext be the result of running UTF-8 decode on the value of cData.") {
        it("Nothing to test.") {
        }
      }

      describe("6. Let C, the client data claimed as used for the signature, be the result of running an implementation-specific JSON parser on JSONtext.") {
        it("Fails if cData is not valid JSON.") {
          val steps = finishAssertion(clientDataJson = "{")
          val step: FinishAssertionSteps#Step6 = steps.begin.next.next.next.next.next.next

          step.validations shouldBe a [Failure[_]]
          step.validations.failed.get shouldBe a [JsonParseException]
          step.next shouldBe a [Failure[_]]
        }

        it("Succeeds if cData is valid JSON.") {
          val steps = finishAssertion(
            clientDataJson = """{
              "challenge": "",
              "origin": "",
              "type": ""
            }"""
          )
          val step: FinishAssertionSteps#Step6 = steps.begin.next.next.next.next.next.next

          step.validations shouldBe a [Success[_]]
          step.clientData should not be null
          step.next shouldBe a [Success[_]]
        }
      }

      describe("7. Verify that the value of C.type is the string webauthn.get.") {
        it("The default test case succeeds.") {
          val steps = finishAssertion()
          val step: FinishAssertionSteps#Step7 = steps.begin.next.next.next.next.next.next.next

          step.validations shouldBe a [Success[_]]
        }

        def assertFails(typeString: String): Unit = {
          val steps = finishAssertion(
            clientDataJson = WebAuthnCodecs.json.writeValueAsString(
              WebAuthnCodecs.json.readTree(Defaults.clientDataJson).asInstanceOf[ObjectNode]
                .set("type", jsonFactory.textNode(typeString))
            )
          )
          val step: FinishAssertionSteps#Step7 = steps.begin.next.next.next.next.next.next.next

          step.validations shouldBe a [Failure[_]]
          step.validations.failed.get shouldBe an [AssertionError]
        }

        it("""Any value other than "webauthn.get" fails.""") {
          forAll { (typeString: String) =>
            whenever (typeString != "webauthn.get") {
              assertFails(typeString)
            }
          }
          forAll(Gen.alphaNumStr) { (typeString: String) =>
            whenever (typeString != "webauthn.get") {
              assertFails(typeString)
            }
          }
        }
      }

      it("8. Verify that the value of C.challenge matches the challenge that was sent to the authenticator in the PublicKeyCredentialRequestOptions passed to the get() call.") {
        val steps = finishAssertion(challenge = Vector.fill(16)(0: Byte))
        val step: FinishAssertionSteps#Step8 = steps.begin.next.next.next.next.next.next.next.next

        step.validations shouldBe a [Failure[_]]
        step.validations.failed.get shouldBe an [AssertionError]
        step.next shouldBe a [Failure[_]]
      }

      it("9. Verify that the value of C.origin matches the Relying Party's origin.") {
        val steps = finishAssertion(origin = "root.evil")
        val step: FinishAssertionSteps#Step9 = steps.begin.next.next.next.next.next.next.next.next.next

        step.validations shouldBe a [Failure[_]]
        step.validations.failed.get shouldBe an [AssertionError]
        step.next shouldBe a [Failure[_]]
      }

      describe("10. Verify that the value of C.tokenBinding.status matches the state of Token Binding for the TLS connection over which the attestation was obtained.") {
        it("Verification succeeds if neither side uses token binding ID.") {
          val steps = finishAssertion()
          val step: FinishAssertionSteps#Step10 = steps.begin.next.next.next.next.next.next.next.next.next.next

          step.validations shouldBe a [Success[_]]
          step.next shouldBe a [Success[_]]
        }

        it("Verification succeeds if client data specifies token binding is unsupported, and RP does not use it.") {
          val clientDataJson = """{"challenge":"AAEBAgMFCA0VIjdZEGl5Yls","origin":"localhost","hashAlgorithm":"SHA-256","tokenBinding":{"status":"not-supported"},"type":"webauthn.get"}"""
          val steps = finishAssertion(clientDataJson = clientDataJson)
          val step: FinishAssertionSteps#Step10 = steps.begin.next.next.next.next.next.next.next.next.next.next

          step.validations shouldBe a [Success[_]]
          step.next shouldBe a [Success[_]]
        }

        it("Verification succeeds if client data specifies token binding is supported, and RP does not use it.") {
          val clientDataJson = """{"challenge":"AAEBAgMFCA0VIjdZEGl5Yls","origin":"localhost","hashAlgorithm":"SHA-256","tokenBinding":{"status":"supported"},"type":"webauthn.get"}"""
          val steps = finishAssertion(clientDataJson = clientDataJson)
          val step: FinishAssertionSteps#Step10 = steps.begin.next.next.next.next.next.next.next.next.next.next

          step.validations shouldBe a [Success[_]]
          step.next shouldBe a [Success[_]]
        }

        it("Verification fails if client data does not specify token binding status and RP specifies token binding ID.") {
          val clientDataJson = """{"challenge":"AAEBAgMFCA0VIjdZEGl5Yls","origin":"localhost","hashAlgorithm":"SHA-256","type":"webauthn.get"}"""
          val steps = finishAssertion(
            callerTokenBindingId = Some("YELLOWSUBMARINE"),
            clientDataJson = clientDataJson
          )
          val step: FinishAssertionSteps#Step10 = steps.begin.next.next.next.next.next.next.next.next.next.next

          step.validations shouldBe a [Failure[_]]
          step.validations.failed.get shouldBe an [IllegalArgumentException]
          step.next shouldBe a [Failure[_]]
        }

        it("Verification succeeds if client data does not specify token binding status and RP does not specify token binding ID.") {
          val clientDataJson = """{"challenge":"AAEBAgMFCA0VIjdZEGl5Yls","origin":"localhost","hashAlgorithm":"SHA-256","type":"webauthn.get"}"""
          val steps = finishAssertion(
            callerTokenBindingId = None,
            clientDataJson = clientDataJson
          )
          val step: FinishAssertionSteps#Step10 = steps.begin.next.next.next.next.next.next.next.next.next.next

          step.validations shouldBe a [Success[_]]
          step.next shouldBe a [Success[_]]
        }
        it("Verification fails if client data specifies token binding ID but RP does not.") {
          val clientDataJson = """{"challenge":"AAEBAgMFCA0VIjdZEGl5Yls","origin":"localhost","hashAlgorithm":"SHA-256","tokenBinding":{"status":"present","id":"YELLOWSUBMARINE"},"type":"webauthn.get"}"""
          val steps = finishAssertion(
            callerTokenBindingId = None,
            clientDataJson = clientDataJson
          )
          val step: FinishAssertionSteps#Step10 = steps.begin.next.next.next.next.next.next.next.next.next.next

          step.validations shouldBe a [Failure[_]]
          step.validations.failed.get shouldBe an [IllegalArgumentException]
          step.next shouldBe a [Failure[_]]
        }

        describe("If Token Binding was used on that TLS connection, also verify that C.tokenBinding.id matches the base64url encoding of the Token Binding ID for the connection.") {
          it("Verification succeeds if both sides specify the same token binding ID.") {
            val clientDataJson = """{"challenge":"AAEBAgMFCA0VIjdZEGl5Yls","origin":"localhost","hashAlgorithm":"SHA-256","tokenBinding":{"status":"present","id":"YELLOWSUBMARINE"},"type":"webauthn.get"}"""
            val steps = finishAssertion(
              callerTokenBindingId = Some("YELLOWSUBMARINE"),
              clientDataJson = clientDataJson
            )
            val step: FinishAssertionSteps#Step10 = steps.begin.next.next.next.next.next.next.next.next.next.next

            step.validations shouldBe a [Success[_]]
            step.next shouldBe a [Success[_]]
          }

          it("Verification fails if ID is missing from tokenBinding in client data.") {
            val clientDataJson = """{"challenge":"AAEBAgMFCA0VIjdZEGl5Yls","origin":"localhost","hashAlgorithm":"SHA-256","tokenBinding":{"status":"present"},"type":"webauthn.get"}"""
            val steps = finishAssertion(
              callerTokenBindingId = Some("YELLOWSUBMARINE"),
              clientDataJson = clientDataJson
            )
            val step: FinishAssertionSteps#Step10 = steps.begin.next.next.next.next.next.next.next.next.next.next

            step.validations shouldBe a [Failure[_]]
            step.validations.failed.get shouldBe an [IllegalArgumentException]
            step.next shouldBe a [Failure[_]]
          }

          it("Verification fails if RP specifies token binding ID but client does not support it.") {
            val clientDataJson = """{"challenge":"AAEBAgMFCA0VIjdZEGl5Yls","origin":"localhost","hashAlgorithm":"SHA-256","tokenBinding":{"status":"not-supported"},"type":"webauthn.get"}"""
            val steps = finishAssertion(
              callerTokenBindingId = Some("YELLOWSUBMARINE"),
              clientDataJson = clientDataJson
            )
            val step: FinishAssertionSteps#Step10 = steps.begin.next.next.next.next.next.next.next.next.next.next

            step.validations shouldBe a [Failure[_]]
            step.validations.failed.get shouldBe an [IllegalArgumentException]
            step.next shouldBe a [Failure[_]]
          }

          it("Verification fails if RP specifies token binding ID but client does not use it.") {
            val clientDataJson = """{"challenge":"AAEBAgMFCA0VIjdZEGl5Yls","origin":"localhost","hashAlgorithm":"SHA-256","tokenBinding":{"status":"supported"},"type":"webauthn.get"}"""
            val steps = finishAssertion(
              callerTokenBindingId = Some("YELLOWSUBMARINE"),
              clientDataJson = clientDataJson
            )
            val step: FinishAssertionSteps#Step10 = steps.begin.next.next.next.next.next.next.next.next.next.next

            step.validations shouldBe a [Failure[_]]
            step.validations.failed.get shouldBe an [IllegalArgumentException]
            step.next shouldBe a [Failure[_]]
          }

          it("Verification fails if client data and RP specify different token binding IDs.") {
            val clientDataJson = """{"challenge":"AAEBAgMFCA0VIjdZEGl5Yls","origin":"localhost","hashAlgorithm":"SHA-256","tokenBinding":{"status":"present","id":"YELLOWSUBMARINE"},"type":"webauthn.get"}"""
            val steps = finishAssertion(
              callerTokenBindingId = Some("ORANGESUBMARINE"),
              clientDataJson = clientDataJson
            )
            val step: FinishAssertionSteps#Step10 = steps.begin.next.next.next.next.next.next.next.next.next.next

            step.validations shouldBe a [Failure[_]]
            step.validations.failed.get shouldBe an [IllegalArgumentException]
            step.next shouldBe a [Failure[_]]
          }
        }
      }

      describe("11. Verify that the rpIdHash in aData is the SHA-256 hash of the RP ID expected by the Relying Party.") {
        it("Fails if RP ID is different.") {
          val steps = finishAssertion(rpId = Defaults.rpId.toBuilder.id("root.evil").build())
          val step: FinishAssertionSteps#Step11 = steps.begin.next.next.next.next.next.next.next.next.next.next.next

          step.validations shouldBe a [Failure[_]]
          step.validations.failed.get shouldBe an [AssertionError]
          step.next shouldBe a [Failure[_]]
        }

        it("Succeeds if RP ID is the same.") {
          val steps = finishAssertion()
          val step: FinishAssertionSteps#Step11 = steps.begin.next.next.next.next.next.next.next.next.next.next.next

          step.validations shouldBe a [Success[_]]
          step.next shouldBe a [Success[_]]
        }
      }

      describe("12. If user verification is required for this assertion, verify that the User Verified bit of the flags in aData is set.") {
        val flagOn: ArrayBuffer = Defaults.authenticatorData.updated(32, (Defaults.authenticatorData(32) | 0x04).toByte)
        val flagOff: ArrayBuffer = Defaults.authenticatorData.updated(32, (Defaults.authenticatorData(32) & 0xfb).toByte)

        it("Succeeds if UV is discouraged and flag is not set.") {
          val steps = finishAssertion(
            userVerificationRequirement = UserVerificationRequirement.DISCOURAGED,
            authenticatorData = flagOff
          )
          val step: FinishAssertionSteps#Step12 = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next

          step.validations shouldBe a [Success[_]]
          step.next shouldBe a [Success[_]]
        }

        it("Succeeds if UV is discouraged and flag is set.") {
          val steps = finishAssertion(
            userVerificationRequirement = UserVerificationRequirement.DISCOURAGED,
            authenticatorData = flagOn
          )
          val step: FinishAssertionSteps#Step12 = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next

          step.validations shouldBe a [Success[_]]
          step.next shouldBe a [Success[_]]
        }

        it("Succeeds if UV is preferred and flag is not set.") {
          val steps = finishAssertion(
            userVerificationRequirement = UserVerificationRequirement.PREFERRED,
            authenticatorData = flagOff
          )
          val step: FinishAssertionSteps#Step12 = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next

          step.validations shouldBe a [Success[_]]
          step.next shouldBe a [Success[_]]
        }

        it("Succeeds if UV is preferred and flag is set.") {
          val steps = finishAssertion(
            userVerificationRequirement = UserVerificationRequirement.PREFERRED,
            authenticatorData = flagOn
          )
          val step: FinishAssertionSteps#Step12 = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next

          step.validations shouldBe a [Success[_]]
          step.next shouldBe a [Success[_]]
        }

        it("Fails if UV is required and flag is not set.") {
          val steps = finishAssertion(
            userVerificationRequirement = UserVerificationRequirement.REQUIRED,
            authenticatorData = flagOff
          )
          val step: FinishAssertionSteps#Step12 = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next

          step.validations shouldBe a [Failure[_]]
          step.validations.failed.get shouldBe an [AssertionError]
          step.next shouldBe a [Failure[_]]
        }

        it("Succeeds if UV is required and flag is set.") {
          val steps = finishAssertion(
            userVerificationRequirement = UserVerificationRequirement.REQUIRED,
            authenticatorData = flagOn
          )
          val step: FinishAssertionSteps#Step12 = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next

          step.validations shouldBe a [Success[_]]
          step.next shouldBe a [Success[_]]
        }
      }

      describe("13. If user verification is not required for this assertion, verify that the User Present bit of the flags in aData is set.") {
        val flagOn: ArrayBuffer = Defaults.authenticatorData.updated(32, (Defaults.authenticatorData(32) | 0x04 | 0x01).toByte)
        val flagOff: ArrayBuffer = Defaults.authenticatorData.updated(32, ((Defaults.authenticatorData(32) | 0x04) & 0xfe).toByte)

        it("Fails if UV is discouraged and flag is not set.") {
          val steps = finishAssertion(
            userVerificationRequirement = UserVerificationRequirement.DISCOURAGED,
            authenticatorData = flagOff
          )
          val step: FinishAssertionSteps#Step13 = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next

          step.validations shouldBe a [Failure[_]]
          step.validations.failed.get shouldBe an [AssertionError]
          step.next shouldBe a [Failure[_]]
        }

        it("Succeeds if UV is discouraged and flag is set.") {
          val steps = finishAssertion(
            userVerificationRequirement = UserVerificationRequirement.DISCOURAGED,
            authenticatorData = flagOn
          )
          val step: FinishAssertionSteps#Step13 = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next

          step.validations shouldBe a [Success[_]]
          step.next shouldBe a [Success[_]]
        }

        it("Fails if UV is preferred and flag is not set.") {
          val steps = finishAssertion(
            userVerificationRequirement = UserVerificationRequirement.PREFERRED,
            authenticatorData = flagOff
          )
          val step: FinishAssertionSteps#Step13 = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next

          step.validations shouldBe a [Failure[_]]
          step.validations.failed.get shouldBe an [AssertionError]
          step.next shouldBe a [Failure[_]]
        }

        it("Succeeds if UV is preferred and flag is set.") {
          val steps = finishAssertion(
            userVerificationRequirement = UserVerificationRequirement.PREFERRED,
            authenticatorData = flagOn
          )
          val step: FinishAssertionSteps#Step13 = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next

          step.validations shouldBe a [Success[_]]
          step.next shouldBe a [Success[_]]
        }

        it("Succeeds if UV is required and flag is not set.") {
          val steps = finishAssertion(
            userVerificationRequirement = UserVerificationRequirement.REQUIRED,
            authenticatorData = flagOff
          )
          val step: FinishAssertionSteps#Step13 = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next

          step.validations shouldBe a [Success[_]]
          step.next shouldBe a [Success[_]]
        }

        it("Succeeds if UV is required and flag is set.") {
          val steps = finishAssertion(
            userVerificationRequirement = UserVerificationRequirement.REQUIRED,
            authenticatorData = flagOn
          )
          val step: FinishAssertionSteps#Step13 = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next

          step.validations shouldBe a [Success[_]]
          step.next shouldBe a [Success[_]]
        }
      }

      describe("14. Verify that the values of the") {

        describe("client extension outputs in clientExtensionResults are as expected, considering the client extension input values that were given as the extensions option in the get() call. In particular, any extension identifier values in the clientExtensionResults MUST be also be present as extension identifier values in the extensions member of options, i.e., no extensions are present that were not requested. In the general case, the meaning of \"are as expected\" is specific to the Relying Party and which extensions are in use.") {
          it("Fails if clientExtensionResults is not a subset of the extensions requested by the Relying Party.") {
            val steps = finishAssertion(
              requestedExtensions = Some(jsonFactory.objectNode()),
              clientExtensionResults = jsonFactory.objectNode().set("foo", jsonFactory.textNode("boo"))
            )
            val step: FinishAssertionSteps#Step14 = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next

            step.validations shouldBe a [Failure[_]]
            step.validations.failed.get shouldBe an [IllegalArgumentException]
            step.next shouldBe a [Failure[_]]
          }

          it("Succeeds if clientExtensionResults is a subset of the extensions requested by the Relying Party.") {
            val steps = finishAssertion(
              requestedExtensions = Some(jsonFactory.objectNode().set("foo", jsonFactory.textNode("bar"))),
              clientExtensionResults = jsonFactory.objectNode().set("foo", jsonFactory.textNode("boo"))
            )
            val step: FinishAssertionSteps#Step14 = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next

            step.validations shouldBe a [Success[_]]
            step.next shouldBe a [Success[_]]
          }
        }

        describe("authenticator extension outputs in the extensions in authData are as expected, considering the client extension input values that were given as the extensions option in the get() call. In particular, any extension identifier values in the extensions in authData MUST be also be present as extension identifier values in the extensions member of options, i.e., no extensions are present that were not requested. In the general case, the meaning of \"are as expected\" is specific to the Relying Party and which extensions are in use.") {
          it("Fails if authenticator extensions is not a subset of the extensions requested by the Relying Party.") {
            val steps = finishAssertion(
              requestedExtensions = Some(jsonFactory.objectNode()),
              authenticatorData = TestAuthenticator.makeAuthDataBytes(
                extensionsCborBytes = Some(WebAuthnCodecs.cbor.writeValueAsBytes(jsonFactory.objectNode().set("foo", jsonFactory.textNode("boo"))).toVector)
              )
            )
            val step: FinishAssertionSteps#Step14 = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next

            step.validations shouldBe a [Failure[_]]
            step.validations.failed.get shouldBe an [IllegalArgumentException]
            step.next shouldBe a [Failure[_]]

          }

          it("Succeeds if authenticator extensions is a subset of the extensions requested by the Relying Party.") {
            val steps = finishAssertion(
              requestedExtensions = Some(jsonFactory.objectNode().set("foo", jsonFactory.textNode("bar"))),
              authenticatorData = TestAuthenticator.makeAuthDataBytes(
                extensionsCborBytes = Some(WebAuthnCodecs.cbor.writeValueAsBytes(jsonFactory.objectNode().set("foo", jsonFactory.textNode("boo"))).toVector)
              )
            )
            val step: FinishAssertionSteps#Step14 = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next

            step.validations shouldBe a [Success[_]]
            step.next shouldBe a [Success[_]]
          }
        }

      }

      it("15. Let hash be the result of computing a hash over the cData using SHA-256.") {
        val steps = finishAssertion()
        val step: FinishAssertionSteps#Step15 = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next

        step.validations shouldBe a [Success[_]]
        step.next shouldBe a [Success[_]]
        step.clientDataJsonHash should equal (MessageDigest.getInstance("SHA-256").digest(Defaults.clientDataJsonBytes.toArray).toVector)
      }

      describe("16. Using the credential public key looked up in step 3, verify that sig is a valid signature over the binary concatenation of aData and hash.") {
        it("The default test case succeeds.") {
          val steps = finishAssertion()
          val step: FinishAssertionSteps#Step16 = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next

          step.validations shouldBe a [Success[_]]
          step.next shouldBe a [Success[_]]
          step.signedBytes should not be null
        }

        it("A mutated clientDataJSON fails verification.") {
          val steps = finishAssertion(
            clientDataJson = WebAuthnCodecs.json.writeValueAsString(
              WebAuthnCodecs.json.readTree(Defaults.clientDataJson).asInstanceOf[ObjectNode]
                .set("foo", jsonFactory.textNode("bar"))
            )
          )
          val step: FinishAssertionSteps#Step16 = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next

          step.validations shouldBe a [Failure[_]]
          step.validations.failed.get shouldBe an [AssertionError]
          step.next shouldBe a [Failure[_]]
        }

        it("A test case with a different signed RP ID hash fails.") {
          val rpId = "ARGHABLARGHLER"
          val rpIdHash: ArrayBuffer = crypto.hash(rpId).toVector
          val steps = finishAssertion(
            authenticatorData = rpIdHash ++ Defaults.authenticatorData.drop(32),
            rpId = Defaults.rpId.toBuilder.id(rpId).build()
          )
          val step: FinishAssertionSteps#Step16 = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next

          step.validations shouldBe a [Failure[_]]
          step.validations.failed.get shouldBe an [AssertionError]
          step.next shouldBe a [Failure[_]]
        }

        it("A test case with a different signed flags field fails.") {
          val steps = finishAssertion(
            authenticatorData = Defaults.authenticatorData.updated(32, (Defaults.authenticatorData(32) | 0x02).toByte)
          )
          val step: FinishAssertionSteps#Step16 = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next

          step.validations shouldBe a [Failure[_]]
          step.validations.failed.get shouldBe an [AssertionError]
          step.next shouldBe a [Failure[_]]
        }

        it("A test case with a different signed signature counter fails.") {
          val steps = finishAssertion(
            authenticatorData = Defaults.authenticatorData.updated(33, 42.toByte)
          )
          val step: FinishAssertionSteps#Step16 = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next

          step.validations shouldBe a [Failure[_]]
          step.validations.failed.get shouldBe an [AssertionError]
          step.next shouldBe a [Failure[_]]
        }
      }

      describe("17. If the signature counter value adata.signCount is nonzero or the value stored in conjunction with credential’s id attribute is nonzero, then run the following sub-step:") {
        describe("If the signature counter value adata.signCount is") {
          describe("greater than the signature counter value stored in conjunction with credential’s id attribute.") {
            val credentialRepository = new CredentialRepository {
              override def lookup(id: Base64UrlString, uh: Base64UrlString) = Some(
                new RegisteredCredential(
                  U2fB64Encoding.decode(id),
                  U2fB64Encoding.decode(uh),
                  Defaults.credentialKey.getPublic,
                  1336L
                )
              ).asJava
              override def lookupAll(id: Base64UrlString) = ???
              override def getCredentialIdsForUsername(username: String): java.util.List[PublicKeyCredentialDescriptor] = ???
              override def getUserHandleForUsername(username: String): Optional[Base64UrlString] = getUserHandleIfDefault(username)
              override def getUsernameForUserHandle(userHandle: Base64UrlString): Optional[String] = ???
            }

            describe("Update the stored signature counter value, associated with credential’s id attribute, to be the value of adata.signCount.") {
              it("An increasing signature counter always succeeds.") {
                val steps = finishAssertion(
                  credentialRepository = Some(credentialRepository),
                  validateSignatureCounter = true
                )
                val step: FinishAssertionSteps#Step17 = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next

                step.validations shouldBe a [Success[_]]
                step.next shouldBe a [Success[_]]
                step.next.result.get.isSignatureCounterValid should be (true)
                step.next.result.get.getSignatureCount should be (1337)
              }
            }
          }

          describe("less than or equal to the signature counter value stored in conjunction with credential’s id attribute. ") {
            val credentialRepository = new CredentialRepository {
              override def lookup(id: Base64UrlString, uh: Base64UrlString) = Some(
                new RegisteredCredential(
                  U2fB64Encoding.decode(id),
                  U2fB64Encoding.decode(uh),
                  Defaults.credentialKey.getPublic,
                  1337L
                )
              ).asJava
              override def lookupAll(id: Base64UrlString) = ???
              override def getCredentialIdsForUsername(username: String): java.util.List[PublicKeyCredentialDescriptor] = ???
              override def getUserHandleForUsername(username: String): Optional[Base64UrlString] = getUserHandleIfDefault(username)
              override def getUsernameForUserHandle(userHandle: Base64UrlString): Optional[String] = ???
            }

            describe("This is a signal that the authenticator may be cloned, i.e. at least two copies of the credential private key may exist and are being used in parallel. Relying Parties should incorporate this information into their risk scoring. Whether the Relying Party updates the stored signature counter value in this case, or not, or fails the authentication ceremony or not, is Relying Party-specific.") {
              it("If signature counter validation is disabled, the a nonincreasing signature counter succeeds.") {
                val steps = finishAssertion(
                  credentialRepository = Some(credentialRepository),
                  validateSignatureCounter = false
                )
                val step: FinishAssertionSteps#Step17 = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next

                step.validations shouldBe a [Success[_]]
                step.next shouldBe a [Success[_]]
                step.next.result.get.isSignatureCounterValid should be(false)
                step.next.result.get.getSignatureCount should be(1337)
              }

              it("If signature counter validation is enabled, the a nonincreasing signature counter fails.") {
                val steps = finishAssertion(
                  credentialRepository = Some(credentialRepository),
                  validateSignatureCounter = true
                )
                val step: FinishAssertionSteps#Step17 = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next

                step.validations shouldBe a [Failure[_]]
                step.validations.failed.get shouldBe an [AssertionError]
                step.next shouldBe a [Failure[_]]
              }
            }
          }
        }
      }

      it("18. If all the above steps are successful, continue with the authentication ceremony as appropriate. Otherwise, fail the authentication ceremony.") {
        val steps = finishAssertion()
        val step: FinishAssertionSteps#Finished = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next

        step.validations shouldBe a [Success[_]]
        steps.run shouldBe a [Success[_]]
        steps.run.isSuccess should be (true)

        step.result.get.isSuccess should be (true)
        step.result.get.getCredentialId should equal (Defaults.credentialId)
        step.result.get.getUserHandle should equal (Defaults.userHandle)
      }

    }

  }

}
