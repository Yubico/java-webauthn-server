// Copyright (c) 2018, Yubico AB
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package com.yubico.webauthn

import com.fasterxml.jackson.core.`type`.TypeReference
import com.fasterxml.jackson.databind.node.JsonNodeFactory
import com.fasterxml.jackson.databind.node.ObjectNode
import com.upokecenter.cbor.CBORObject
import com.yubico.fido.metadata.KeyProtectionType
import com.yubico.fido.metadata.MatcherProtectionType
import com.yubico.fido.metadata.UserVerificationMethod
import com.yubico.internal.util.JacksonCodecs
import com.yubico.internal.util.scala.JavaConverters._
import com.yubico.webauthn.data.AssertionExtensionInputs
import com.yubico.webauthn.data.AuthenticatorAssertionResponse
import com.yubico.webauthn.data.ByteArray
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs
import com.yubico.webauthn.data.CollectedClientData
import com.yubico.webauthn.data.Extensions.LargeBlob.LargeBlobAuthenticationInput
import com.yubico.webauthn.data.Extensions.Uvm.UvmEntry
import com.yubico.webauthn.data.Generators._
import com.yubico.webauthn.data.PublicKeyCredential
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions
import com.yubico.webauthn.data.ReexportHelpers
import com.yubico.webauthn.data.RelyingPartyIdentity
import com.yubico.webauthn.data.UserIdentity
import com.yubico.webauthn.data.UserVerificationRequirement
import com.yubico.webauthn.exception.InvalidSignatureCountException
import com.yubico.webauthn.extension.appid.AppId
import com.yubico.webauthn.test.Helpers
import com.yubico.webauthn.test.Util.toStepWithUtilities
import org.junit.runner.RunWith
import org.scalacheck.Gen
import org.scalatest.FunSpec
import org.scalatest.Matchers
import org.scalatestplus.junit.JUnitRunner
import org.scalatestplus.scalacheck.ScalaCheckDrivenPropertyChecks

import java.io.IOException
import java.nio.charset.Charset
import java.security.KeyPair
import java.security.MessageDigest
import java.security.interfaces.ECPublicKey
import java.util.Optional
import scala.jdk.CollectionConverters._
import scala.util.Failure
import scala.util.Success
import scala.util.Try

@RunWith(classOf[JUnitRunner])
class RelyingPartyAssertionSpec
    extends FunSpec
    with Matchers
    with ScalaCheckDrivenPropertyChecks
    with TestWithEachProvider {

  private def jsonFactory: JsonNodeFactory = JsonNodeFactory.instance

  private def sha256(bytes: ByteArray): ByteArray = Crypto.sha256(bytes)
  private def sha256(data: String): ByteArray =
    sha256(new ByteArray(data.getBytes(Charset.forName("UTF-8"))))

  private object Defaults {

    val rpId =
      RelyingPartyIdentity.builder().id("localhost").name("Test party").build()

    // These values were generated using TestAuthenticator.makeAssertionExample()
    val authenticatorData: ByteArray =
      ByteArray.fromHex("49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630100000539")
    val clientDataJson: String =
      """{"challenge":"AAEBAgMFCA0VIjdZEGl5Yls","origin":"https://localhost","type":"webauthn.get","tokenBinding":{"status":"supported"},"clientExtensions":{}}"""
    val credentialId: ByteArray =
      ByteArray.fromBase64Url("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")
    val credentialKey: KeyPair = TestAuthenticator.importEcKeypair(
      privateBytes =
        ByteArray.fromHex("308193020100301306072a8648ce3d020106082a8648ce3d030107047930770201010420449d91b8a2a508b2927cd5cf4dde32db8e58f237fc155e395d3aad127e115f5aa00a06082a8648ce3d030107a1440342000446c68a2eb75057b1f19b6d06dd3733381063d021391b3637889b0b432c54aaa2b184b35e44d433c70e63a9dd82568dd1ec02c5daba3e66b90a3a881c0c1f4c1a"),
      publicBytes =
        ByteArray.fromHex("3059301306072a8648ce3d020106082a8648ce3d0301070342000446c68a2eb75057b1f19b6d06dd3733381063d021391b3637889b0b432c54aaa2b184b35e44d433c70e63a9dd82568dd1ec02c5daba3e66b90a3a881c0c1f4c1a"),
    )
    val signature: ByteArray =
      ByteArray.fromHex("304502201dfef99d44222410686605e23227853f19e9bf89cbab181fdb52b7f40d79f0d5022100c167309d699a03416887af363de0628d7d77f678a01d135da996f0ecbed7e8a5")

    // These values are not signed over
    val username: String = "foo-user"
    val userHandle: ByteArray =
      ByteArray.fromHex("6d8972d9603ce4f3fa5d520ce6d024bf")
    val user: UserIdentity = UserIdentity
      .builder()
      .name(username)
      .displayName("Test user")
      .id(userHandle)
      .build()

    // These values are defined by the attestationObject and clientDataJson above
    val clientDataJsonBytes: ByteArray = new ByteArray(
      clientDataJson.getBytes("UTF-8")
    )
    val clientData = new CollectedClientData(clientDataJsonBytes)
    val challenge: ByteArray = clientData.getChallenge
    val requestedExtensions = AssertionExtensionInputs.builder().build()
    val clientExtensionResults: ClientAssertionExtensionOutputs =
      ClientAssertionExtensionOutputs.builder().build()

  }

  private def getUserHandleIfDefaultUsername(
      username: String,
      userHandle: ByteArray,
  ): Optional[ByteArray] =
    if (username == Defaults.username)
      Some(userHandle).asJava
    else
      ???

  private def getUsernameIfDefaultUserHandle(
      userHandle: ByteArray,
      username: String,
  ): Optional[String] =
    if (userHandle == Defaults.userHandle)
      Some(username).asJava
    else
      ???

  private def getPublicKeyBytes(credentialKey: KeyPair): ByteArray =
    WebAuthnTestCodecs.ecPublicKeyToCose(
      credentialKey.getPublic.asInstanceOf[ECPublicKey]
    )

  def finishAssertion(
      allowCredentials: Option[java.util.List[PublicKeyCredentialDescriptor]] =
        Some(
          List(
            PublicKeyCredentialDescriptor
              .builder()
              .id(Defaults.credentialId)
              .build()
          ).asJava
        ),
      allowOriginPort: Boolean = false,
      allowOriginSubdomain: Boolean = false,
      allowUnrequestedExtensions: Boolean = false,
      authenticatorData: ByteArray = Defaults.authenticatorData,
      callerTokenBindingId: Option[ByteArray] = None,
      challenge: ByteArray = Defaults.challenge,
      clientDataJson: String = Defaults.clientDataJson,
      clientExtensionResults: ClientAssertionExtensionOutputs =
        Defaults.clientExtensionResults,
      credentialId: ByteArray = Defaults.credentialId,
      credentialKey: KeyPair = Defaults.credentialKey,
      credentialRepository: Option[CredentialRepository] = None,
      origins: Option[Set[String]] = None,
      requestedExtensions: AssertionExtensionInputs =
        Defaults.requestedExtensions,
      rpId: RelyingPartyIdentity = Defaults.rpId,
      signature: ByteArray = Defaults.signature,
      userHandleForResponse: ByteArray = Defaults.userHandle,
      userHandleForUser: ByteArray = Defaults.userHandle,
      usernameForRequest: Option[String] = Some(Defaults.username),
      usernameForUser: String = Defaults.username,
      userVerificationRequirement: UserVerificationRequirement =
        UserVerificationRequirement.PREFERRED,
      validateSignatureCounter: Boolean = true,
  ): FinishAssertionSteps = {
    val clientDataJsonBytes: ByteArray =
      if (clientDataJson == null) null
      else new ByteArray(clientDataJson.getBytes("UTF-8"))
    val credentialPublicKeyBytes = getPublicKeyBytes(credentialKey)

    val request = AssertionRequest
      .builder()
      .publicKeyCredentialRequestOptions(
        PublicKeyCredentialRequestOptions
          .builder()
          .challenge(challenge)
          .rpId(rpId.getId)
          .allowCredentials(allowCredentials.asJava)
          .userVerification(userVerificationRequirement)
          .extensions(requestedExtensions)
          .build()
      )
      .username(usernameForRequest.asJava)
      .build()

    val response = PublicKeyCredential
      .builder()
      .id(credentialId)
      .response(
        AuthenticatorAssertionResponse
          .builder()
          .authenticatorData(
            if (authenticatorData == null) null else authenticatorData
          )
          .clientDataJSON(
            if (clientDataJsonBytes == null) null else clientDataJsonBytes
          )
          .signature(if (signature == null) null else signature)
          .userHandle(userHandleForResponse)
          .build()
      )
      .clientExtensionResults(clientExtensionResults)
      .build()

    val builder = RelyingParty
      .builder()
      .identity(rpId)
      .credentialRepository(
        credentialRepository getOrElse new CredentialRepository {
          override def lookup(credId: ByteArray, lookupUserHandle: ByteArray) =
            (
              if (credId == credentialId)
                Some(
                  RegisteredCredential
                    .builder()
                    .credentialId(credId)
                    .userHandle(userHandleForUser)
                    .publicKeyCose(credentialPublicKeyBytes)
                    .signatureCount(0)
                    .build()
                )
              else None
            ).asJava
          override def lookupAll(credId: ByteArray) =
            lookup(credId, null).asScala.toSet.asJava
          override def getCredentialIdsForUsername(username: String) = ???
          override def getUserHandleForUsername(username: String)
              : Optional[ByteArray] =
            getUserHandleIfDefaultUsername(
              username,
              userHandle = userHandleForUser,
            )
          override def getUsernameForUserHandle(userHandle: ByteArray)
              : Optional[String] =
            getUsernameIfDefaultUserHandle(
              userHandle,
              username = usernameForUser,
            )
        }
      )
      .preferredPubkeyParams(Nil.asJava)
      .allowOriginPort(allowOriginPort)
      .allowOriginSubdomain(allowOriginSubdomain)
      .allowUntrustedAttestation(false)
      .allowUnrequestedExtensions(allowUnrequestedExtensions)
      .validateSignatureCounter(validateSignatureCounter)

    origins.map(_.asJava).foreach(builder.origins _)

    builder
      .build()
      ._finishAssertion(request, response, callerTokenBindingId.asJava)
  }

  testWithEachProvider { it =>
    describe("RelyingParty.startAssertion") {

      describe(
        "respects the userVerification parameter in StartAssertionOptions."
      ) {

        val default = UserVerificationRequirement.PREFERRED

        it(s"If the parameter is not set, or set to empty, the default of ${default} is used.") {
          val rp = RelyingParty
            .builder()
            .identity(Defaults.rpId)
            .credentialRepository(Helpers.CredentialRepository.empty)
            .build()
          val request1 =
            rp.startAssertion(StartAssertionOptions.builder().build())
          val request2 = rp.startAssertion(
            StartAssertionOptions
              .builder()
              .userVerification(Optional.empty[UserVerificationRequirement])
              .build()
          )

          request1.getPublicKeyCredentialRequestOptions.getUserVerification should equal(
            default
          )
          request2.getPublicKeyCredentialRequestOptions.getUserVerification should equal(
            default
          )
        }

        it(s"If the parameter is set, that value is used.") {
          val rp = RelyingParty
            .builder()
            .identity(Defaults.rpId)
            .credentialRepository(Helpers.CredentialRepository.empty)
            .build()

          forAll { uv: UserVerificationRequirement =>
            val request = rp.startAssertion(
              StartAssertionOptions.builder().userVerification(uv).build()
            )

            request.getPublicKeyCredentialRequestOptions.getUserVerification should equal(
              uv
            )
          }
        }
      }

    }

    describe("§7.2. Verifying an authentication assertion") {

      describe("When verifying a given PublicKeyCredential structure (credential) and an AuthenticationExtensionsClientOutputs structure clientExtensionResults, as part of an authentication ceremony, the Relying Party MUST proceed as follows:") {

        describe("1. If the allowCredentials option was given when this authentication ceremony was initiated, verify that credential.id identifies one of the public key credentials that were listed in allowCredentials.") {
          it("Fails if returned credential ID is a requested one.") {
            val steps = finishAssertion(
              allowCredentials = Some(
                List(
                  PublicKeyCredentialDescriptor
                    .builder()
                    .id(new ByteArray(Array(3, 2, 1, 0)))
                    .build()
                ).asJava
              ),
              credentialId = new ByteArray(Array(0, 1, 2, 3)),
            )
            val step: FinishAssertionSteps#Step1 = steps.begin.next

            toStepWithUtilities(step).validations shouldBe a[Failure[_]]
            step.validations.failed.get shouldBe an[IllegalArgumentException]
            step.tryNext shouldBe a[Failure[_]]
          }

          it("Succeeds if returned credential ID is a requested one.") {
            val steps = finishAssertion(
              allowCredentials = Some(
                List(
                  PublicKeyCredentialDescriptor
                    .builder()
                    .id(new ByteArray(Array(0, 1, 2, 3)))
                    .build(),
                  PublicKeyCredentialDescriptor
                    .builder()
                    .id(new ByteArray(Array(4, 5, 6, 7)))
                    .build(),
                ).asJava
              ),
              credentialId = new ByteArray(Array(4, 5, 6, 7)),
            )
            val step: FinishAssertionSteps#Step1 = steps.begin.next

            step.validations shouldBe a[Success[_]]
            step.tryNext shouldBe a[Success[_]]
          }

          it("Succeeds if returned no credential IDs were requested.") {
            val steps = finishAssertion(
              allowCredentials = None,
              credentialId = new ByteArray(Array(0, 1, 2, 3)),
            )
            val step: FinishAssertionSteps#Step1 = steps.begin.next

            step.validations shouldBe a[Success[_]]
            step.tryNext shouldBe a[Success[_]]
          }
        }

        describe("2. Identify the user being authenticated and verify that this user is the owner of the public key credential source credentialSource identified by credential.id:") {
          object owner {
            val username = "owner"
            val userHandle = new ByteArray(Array(4, 5, 6, 7))
          }
          object nonOwner {
            val username = "non-owner"
            val userHandle = new ByteArray(Array(8, 9, 10, 11))
          }

          val credentialRepository = Some(new CredentialRepository {
            override def lookup(id: ByteArray, uh: ByteArray) =
              Some(
                RegisteredCredential
                  .builder()
                  .credentialId(new ByteArray(Array(0, 1, 2, 3)))
                  .userHandle(owner.userHandle)
                  .publicKeyCose(getPublicKeyBytes(Defaults.credentialKey))
                  .signatureCount(0)
                  .build()
              ).asJava
            override def lookupAll(id: ByteArray) = ???
            override def getCredentialIdsForUsername(username: String) = ???
            override def getUserHandleForUsername(
                username: String
            ): Optional[ByteArray] =
              Some(
                if (username == owner.username) owner.userHandle
                else nonOwner.userHandle
              ).asJava
            override def getUsernameForUserHandle(
                userHandle: ByteArray
            ): Optional[String] =
              Some(
                if (userHandle == owner.userHandle) owner.username
                else nonOwner.username
              ).asJava
          })

          describe("If the user was identified before the authentication ceremony was initiated, verify that the identified user is the owner of credentialSource. If credential.response.userHandle is present, verify that this value identifies the same user as was previously identified.") {
            it(
              "Fails if credential ID is not owned by the given user handle."
            ) {
              val steps = finishAssertion(
                credentialRepository = credentialRepository,
                usernameForRequest = Some(owner.username),
                userHandleForUser = owner.userHandle,
                userHandleForResponse = nonOwner.userHandle,
              )
              val step: FinishAssertionSteps#Step2 = steps.begin.next.next

              step.validations shouldBe a[Failure[_]]
              step.validations.failed.get shouldBe an[IllegalArgumentException]
              step.tryNext shouldBe a[Failure[_]]
            }

            it("Succeeds if credential ID is owned by the given user handle.") {
              val steps = finishAssertion(
                credentialRepository = credentialRepository,
                usernameForRequest = Some(owner.username),
                userHandleForUser = owner.userHandle,
                userHandleForResponse = owner.userHandle,
              )
              val step: FinishAssertionSteps#Step2 = steps.begin.next.next

              step.validations shouldBe a[Success[_]]
              step.tryNext shouldBe a[Success[_]]
            }
          }

          describe("If the user was not identified before the authentication ceremony was initiated, verify that credential.response.userHandle is present, and that the user identified by this value is the owner of credentialSource.") {
            it(
              "Fails if credential ID is not owned by the given user handle."
            ) {
              val steps = finishAssertion(
                credentialRepository = credentialRepository,
                usernameForRequest = None,
                userHandleForUser = owner.userHandle,
                userHandleForResponse = nonOwner.userHandle,
              )
              val step: FinishAssertionSteps#Step2 = steps.begin.next.next

              step.validations shouldBe a[Failure[_]]
              step.validations.failed.get shouldBe an[IllegalArgumentException]
              step.tryNext shouldBe a[Failure[_]]
            }

            it("Succeeds if credential ID is owned by the given user handle.") {
              val steps = finishAssertion(
                credentialRepository = credentialRepository,
                usernameForRequest = None,
                userHandleForUser = owner.userHandle,
                userHandleForResponse = owner.userHandle,
              )
              val step: FinishAssertionSteps#Step2 = steps.begin.next.next

              step.validations shouldBe a[Success[_]]
              step.tryNext shouldBe a[Success[_]]
            }
          }
        }

        describe("3. Using credential’s id attribute (or the corresponding rawId, if base64url encoding is inappropriate for your use case), look up the corresponding credential public key.") {
          it("Fails if the credential ID is unknown.") {
            val steps = finishAssertion(
              credentialRepository = Some(Helpers.CredentialRepository.empty)
            )
            val step: steps.Step3 = new steps.Step3(
              Defaults.username,
              Defaults.userHandle,
              Nil.asJava,
            )

            step.validations shouldBe a[Failure[_]]
            step.validations.failed.get shouldBe an[IllegalArgumentException]
            step.tryNext shouldBe a[Failure[_]]
          }

          it("Succeeds if the credential ID is known.") {
            val steps = finishAssertion(
              credentialRepository = Some(
                Helpers.CredentialRepository.withUser(
                  Defaults.user,
                  RegisteredCredential
                    .builder()
                    .credentialId(Defaults.credentialId)
                    .userHandle(Defaults.userHandle)
                    .publicKeyCose(getPublicKeyBytes(Defaults.credentialKey))
                    .signatureCount(0)
                    .build(),
                )
              )
            )
            val step: FinishAssertionSteps#Step3 = steps.begin.next.next.next

            step.validations shouldBe a[Success[_]]
            step.credential.getPublicKeyCose should equal(
              getPublicKeyBytes(Defaults.credentialKey)
            )
            step.tryNext shouldBe a[Success[_]]
          }
        }

        describe("4. Let cData, authData and sig denote the value of credential’s response's clientDataJSON, authenticatorData, and signature respectively.") {
          it("Succeeds if all three are present.") {
            val steps = finishAssertion()
            val step: FinishAssertionSteps#Step4 =
              steps.begin.next.next.next.next

            step.validations shouldBe a[Success[_]]
            step.clientData should not be null
            step.authenticatorData should not be null
            step.signature should not be null
            step.tryNext shouldBe a[Success[_]]
          }

          it("Fails if clientDataJSON is missing.") {
            a[NullPointerException] should be thrownBy finishAssertion(
              clientDataJson = null
            )
          }

          it("Fails if authenticatorData is missing.") {
            a[NullPointerException] should be thrownBy finishAssertion(
              authenticatorData = null
            )
          }

          it("Fails if signature is missing.") {
            a[NullPointerException] should be thrownBy finishAssertion(
              signature = null
            )
          }
        }

        describe("5. Let JSONtext be the result of running UTF-8 decode on the value of cData.") {
          it("Nothing to test.") {}
        }

        describe("6. Let C, the client data claimed as used for the signature, be the result of running an implementation-specific JSON parser on JSONtext.") {
          it("Fails if cData is not valid JSON.") {
            an[IOException] should be thrownBy new CollectedClientData(
              new ByteArray("{".getBytes(Charset.forName("UTF-8")))
            )
            an[IOException] should be thrownBy finishAssertion(clientDataJson =
              "{"
            )
          }

          it("Succeeds if cData is valid JSON.") {
            val steps = finishAssertion(
              clientDataJson = """{
                "challenge": "",
                "origin": "",
                "type": ""
              }"""
            )
            val step: FinishAssertionSteps#Step6 =
              steps.begin.next.next.next.next.next.next

            step.validations shouldBe a[Success[_]]
            step.clientData should not be null
            step.tryNext shouldBe a[Success[_]]
          }
        }

        describe(
          "7. Verify that the value of C.type is the string webauthn.get."
        ) {
          it("The default test case succeeds.") {
            val steps = finishAssertion()
            val step: FinishAssertionSteps#Step7 =
              steps.begin.next.next.next.next.next.next.next

            step.validations shouldBe a[Success[_]]
          }

          def assertFails(typeString: String): Unit = {
            val steps = finishAssertion(
              clientDataJson = JacksonCodecs.json.writeValueAsString(
                JacksonCodecs.json
                  .readTree(Defaults.clientDataJson)
                  .asInstanceOf[ObjectNode]
                  .set("type", jsonFactory.textNode(typeString))
              )
            )
            val step: FinishAssertionSteps#Step7 =
              steps.begin.next.next.next.next.next.next.next

            step.validations shouldBe a[Failure[_]]
            step.validations.failed.get shouldBe an[IllegalArgumentException]
          }

          it("""Any value other than "webauthn.get" fails.""") {
            forAll { (typeString: String) =>
              whenever(typeString != "webauthn.get") {
                assertFails(typeString)
              }
            }
            forAll(Gen.alphaNumStr) { (typeString: String) =>
              whenever(typeString != "webauthn.get") {
                assertFails(typeString)
              }
            }
          }
        }

        it("8. Verify that the value of C.challenge matches the challenge that was sent to the authenticator in the PublicKeyCredentialRequestOptions passed to the get() call.") {
          val steps =
            finishAssertion(challenge = new ByteArray(Array.fill(16)(0)))
          val step: FinishAssertionSteps#Step8 =
            steps.begin.next.next.next.next.next.next.next.next

          step.validations shouldBe a[Failure[_]]
          step.validations.failed.get shouldBe an[IllegalArgumentException]
          step.tryNext shouldBe a[Failure[_]]
        }

        describe("9. Verify that the value of C.origin matches the Relying Party's origin.") {
          def checkAccepted(
              origin: String,
              origins: Option[Set[String]] = None,
              allowOriginPort: Boolean = false,
              allowOriginSubdomain: Boolean = false,
          ): Unit = {
            val clientDataJson: String = Defaults.clientDataJson.replace(
              "\"https://localhost\"",
              "\"" + origin + "\"",
            )
            val steps = finishAssertion(
              clientDataJson = clientDataJson,
              origins = origins,
              allowOriginPort = allowOriginPort,
              allowOriginSubdomain = allowOriginSubdomain,
            )
            val step: FinishAssertionSteps#Step9 =
              steps.begin.next.next.next.next.next.next.next.next.next

            step.validations shouldBe a[Success[_]]
            step.tryNext shouldBe a[Success[_]]
          }

          def checkRejected(
              origin: String,
              origins: Option[Set[String]] = None,
              allowOriginPort: Boolean = false,
              allowOriginSubdomain: Boolean = false,
          ): Unit = {
            val clientDataJson: String = Defaults.clientDataJson.replace(
              "\"https://localhost\"",
              "\"" + origin + "\"",
            )
            val steps = finishAssertion(
              clientDataJson = clientDataJson,
              origins = origins,
              allowOriginPort = allowOriginPort,
              allowOriginSubdomain = allowOriginSubdomain,
            )
            val step: FinishAssertionSteps#Step9 =
              steps.begin.next.next.next.next.next.next.next.next.next

            step.validations shouldBe a[Failure[_]]
            step.validations.failed.get shouldBe an[IllegalArgumentException]
            step.tryNext shouldBe a[Failure[_]]
          }

          it("Fails if origin is different.") {
            checkRejected(origin = "https://root.evil")
          }

          describe("Explicit ports are") {
            val origin = "https://localhost:8080"

            it("by default not allowed.") {
              checkRejected(origin = origin)
            }

            it("allowed if RP opts in to it.") {
              checkAccepted(origin = origin, allowOriginPort = true)
            }
          }

          describe("Subdomains are") {
            val origin = "https://foo.localhost"

            it("by default not allowed.") {
              checkRejected(origin = origin)
            }

            it("allowed if RP opts in to it.") {
              checkAccepted(origin = origin, allowOriginSubdomain = true)
            }
          }

          describe("Subdomains and explicit ports at the same time are") {
            val origin = "https://foo.localhost:8080"

            it("by default not allowed.") {
              checkRejected(origin = origin)
            }

            it("not allowed if only subdomains are allowed.") {
              checkRejected(origin = origin, allowOriginSubdomain = true)
            }

            it("not allowed if only explicit ports are allowed.") {
              checkRejected(origin = origin, allowOriginPort = true)
            }

            it("allowed if RP opts in to both.") {
              checkAccepted(
                origin = origin,
                allowOriginPort = true,
                allowOriginSubdomain = true,
              )
            }
          }

          describe("The examples in JavaDoc are correct:") {
            def check(
                origins: Set[String],
                acceptOrigins: Iterable[String],
                rejectOrigins: Iterable[String],
                allowOriginPort: Boolean = false,
                allowOriginSubdomain: Boolean = false,
            ): Unit = {
              for { origin <- acceptOrigins } {
                it(s"${origin} is accepted.") {
                  checkAccepted(
                    origin = origin,
                    origins = Some(origins),
                    allowOriginPort = allowOriginPort,
                    allowOriginSubdomain = allowOriginSubdomain,
                  )
                }
              }

              for { origin <- rejectOrigins } {
                it(s"${origin} is rejected.") {
                  checkRejected(
                    origin = origin,
                    origins = Some(origins),
                    allowOriginPort = allowOriginPort,
                    allowOriginSubdomain = allowOriginSubdomain,
                  )
                }
              }
            }

            describe("For allowOriginPort:") {
              val origins = Set(
                "https://example.org",
                "https://accounts.example.org",
                "https://acme.com:8443",
              )

              describe("false,") {
                check(
                  origins = origins,
                  acceptOrigins = List(
                    "https://example.org",
                    "https://accounts.example.org",
                    "https://acme.com:8443",
                  ),
                  rejectOrigins = List(
                    "https://example.org:8443",
                    "https://shop.example.org",
                    "https://acme.com",
                    "https://acme.com:9000",
                  ),
                  allowOriginPort = false,
                )
              }

              describe("true,") {
                check(
                  origins = origins,
                  acceptOrigins = List(
                    "https://example.org",
                    "https://example.org:8443",
                    "https://accounts.example.org",
                    "https://acme.com",
                    "https://acme.com:8443",
                    "https://acme.com:9000",
                  ),
                  rejectOrigins = List(
                    "https://shop.example.org"
                  ),
                  allowOriginPort = true,
                )
              }
            }

            describe("For allowOriginSubdomain:") {
              val origins = Set("https://example.org", "https://acme.com:8443")

              describe("false,") {
                check(
                  origins = origins,
                  acceptOrigins = List(
                    "https://example.org",
                    "https://acme.com:8443",
                  ),
                  rejectOrigins = List(
                    "https://example.org:8443",
                    "https://accounts.example.org",
                    "https://acme.com",
                    "https://shop.acme.com:8443",
                  ),
                  allowOriginSubdomain = false,
                )
              }

              describe("true,") {
                check(
                  origins = origins,
                  acceptOrigins = List(
                    "https://example.org",
                    "https://accounts.example.org",
                    "https://acme.com:8443",
                    "https://shop.acme.com:8443",
                  ),
                  rejectOrigins = List(
                    "https://example.org:8443",
                    "https://acme.com",
                  ),
                  allowOriginSubdomain = true,
                )
              }
            }
          }
        }

        describe("10. Verify that the value of C.tokenBinding.status matches the state of Token Binding for the TLS connection over which the attestation was obtained.") {
          it("Verification succeeds if neither side uses token binding ID.") {
            val steps = finishAssertion()
            val step: FinishAssertionSteps#Step10 =
              steps.begin.next.next.next.next.next.next.next.next.next.next

            step.validations shouldBe a[Success[_]]
            step.tryNext shouldBe a[Success[_]]
          }

          it("Verification succeeds if client data specifies token binding is unsupported, and RP does not use it.") {
            val clientDataJson =
              """{"challenge":"AAEBAgMFCA0VIjdZEGl5Yls","origin":"https://localhost","hashAlgorithm":"SHA-256","type":"webauthn.get"}"""
            val steps = finishAssertion(clientDataJson = clientDataJson)
            val step: FinishAssertionSteps#Step10 =
              steps.begin.next.next.next.next.next.next.next.next.next.next

            step.validations shouldBe a[Success[_]]
            step.tryNext shouldBe a[Success[_]]
          }

          it("Verification succeeds if client data specifies token binding is supported, and RP does not use it.") {
            val clientDataJson =
              """{"challenge":"AAEBAgMFCA0VIjdZEGl5Yls","origin":"https://localhost","hashAlgorithm":"SHA-256","tokenBinding":{"status":"supported"},"type":"webauthn.get"}"""
            val steps = finishAssertion(clientDataJson = clientDataJson)
            val step: FinishAssertionSteps#Step10 =
              steps.begin.next.next.next.next.next.next.next.next.next.next

            step.validations shouldBe a[Success[_]]
            step.tryNext shouldBe a[Success[_]]
          }

          it("Verification fails if client data does not specify token binding status and RP specifies token binding ID.") {
            val clientDataJson =
              """{"challenge":"AAEBAgMFCA0VIjdZEGl5Yls","origin":"https://localhost","hashAlgorithm":"SHA-256","type":"webauthn.get"}"""
            val steps = finishAssertion(
              callerTokenBindingId =
                Some(ByteArray.fromBase64Url("YELLOWSUBMARINE")),
              clientDataJson = clientDataJson,
            )
            val step: FinishAssertionSteps#Step10 =
              steps.begin.next.next.next.next.next.next.next.next.next.next

            step.validations shouldBe a[Failure[_]]
            step.validations.failed.get shouldBe an[IllegalArgumentException]
            step.tryNext shouldBe a[Failure[_]]
          }

          it("Verification succeeds if client data does not specify token binding status and RP does not specify token binding ID.") {
            val clientDataJson =
              """{"challenge":"AAEBAgMFCA0VIjdZEGl5Yls","origin":"https://localhost","hashAlgorithm":"SHA-256","type":"webauthn.get"}"""
            val steps = finishAssertion(
              callerTokenBindingId = None,
              clientDataJson = clientDataJson,
            )
            val step: FinishAssertionSteps#Step10 =
              steps.begin.next.next.next.next.next.next.next.next.next.next

            step.validations shouldBe a[Success[_]]
            step.tryNext shouldBe a[Success[_]]
          }
          it("Verification fails if client data specifies token binding ID but RP does not.") {
            val clientDataJson =
              """{"challenge":"AAEBAgMFCA0VIjdZEGl5Yls","origin":"https://localhost","hashAlgorithm":"SHA-256","tokenBinding":{"status":"present","id":"YELLOWSUBMARINE"},"type":"webauthn.get"}"""
            val steps = finishAssertion(
              callerTokenBindingId = None,
              clientDataJson = clientDataJson,
            )
            val step: FinishAssertionSteps#Step10 =
              steps.begin.next.next.next.next.next.next.next.next.next.next

            step.validations shouldBe a[Failure[_]]
            step.validations.failed.get shouldBe an[IllegalArgumentException]
            step.tryNext shouldBe a[Failure[_]]
          }

          describe("If Token Binding was used on that TLS connection, also verify that C.tokenBinding.id matches the base64url encoding of the Token Binding ID for the connection.") {
            it("Verification succeeds if both sides specify the same token binding ID.") {
              val clientDataJson =
                """{"challenge":"AAEBAgMFCA0VIjdZEGl5Yls","origin":"https://localhost","hashAlgorithm":"SHA-256","tokenBinding":{"status":"present","id":"YELLOWSUBMARINE"},"type":"webauthn.get"}"""
              val steps = finishAssertion(
                callerTokenBindingId =
                  Some(ByteArray.fromBase64Url("YELLOWSUBMARINE")),
                clientDataJson = clientDataJson,
              )
              val step: FinishAssertionSteps#Step10 =
                steps.begin.next.next.next.next.next.next.next.next.next.next

              step.validations shouldBe a[Success[_]]
              step.tryNext shouldBe a[Success[_]]
            }

            it("Verification fails if ID is missing from tokenBinding in client data.") {
              val clientDataJson =
                """{"challenge":"AAEBAgMFCA0VIjdZEGl5Yls","origin":"https://localhost","hashAlgorithm":"SHA-256","tokenBinding":{"status":"present"},"type":"webauthn.get"}"""
              val steps = finishAssertion(
                callerTokenBindingId =
                  Some(ByteArray.fromBase64Url("YELLOWSUBMARINE")),
                clientDataJson = clientDataJson,
              )
              val step: FinishAssertionSteps#Step10 =
                steps.begin.next.next.next.next.next.next.next.next.next.next

              step.validations shouldBe a[Failure[_]]
              step.validations.failed.get shouldBe an[IllegalArgumentException]
              step.tryNext shouldBe a[Failure[_]]
            }

            it("Verification fails if RP specifies token binding ID but client does not support it.") {
              val clientDataJson =
                """{"challenge":"AAEBAgMFCA0VIjdZEGl5Yls","origin":"https://localhost","hashAlgorithm":"SHA-256","type":"webauthn.get"}"""
              val steps = finishAssertion(
                callerTokenBindingId =
                  Some(ByteArray.fromBase64Url("YELLOWSUBMARINE")),
                clientDataJson = clientDataJson,
              )
              val step: FinishAssertionSteps#Step10 =
                steps.begin.next.next.next.next.next.next.next.next.next.next

              step.validations shouldBe a[Failure[_]]
              step.validations.failed.get shouldBe an[IllegalArgumentException]
              step.tryNext shouldBe a[Failure[_]]
            }

            it("Verification fails if RP specifies token binding ID but client does not use it.") {
              val clientDataJson =
                """{"challenge":"AAEBAgMFCA0VIjdZEGl5Yls","origin":"https://localhost","hashAlgorithm":"SHA-256","tokenBinding":{"status":"supported"},"type":"webauthn.get"}"""
              val steps = finishAssertion(
                callerTokenBindingId =
                  Some(ByteArray.fromBase64Url("YELLOWSUBMARINE")),
                clientDataJson = clientDataJson,
              )
              val step: FinishAssertionSteps#Step10 =
                steps.begin.next.next.next.next.next.next.next.next.next.next

              step.validations shouldBe a[Failure[_]]
              step.validations.failed.get shouldBe an[IllegalArgumentException]
              step.tryNext shouldBe a[Failure[_]]
            }

            it("Verification fails if client data and RP specify different token binding IDs.") {
              val clientDataJson =
                """{"challenge":"AAEBAgMFCA0VIjdZEGl5Yls","origin":"https://localhost","hashAlgorithm":"SHA-256","tokenBinding":{"status":"present","id":"YELLOWSUBMARINE"},"type":"webauthn.get"}"""
              val steps = finishAssertion(
                callerTokenBindingId =
                  Some(ByteArray.fromBase64Url("ORANGESUBMARINE")),
                clientDataJson = clientDataJson,
              )
              val step: FinishAssertionSteps#Step10 =
                steps.begin.next.next.next.next.next.next.next.next.next.next

              step.validations shouldBe a[Failure[_]]
              step.validations.failed.get shouldBe an[IllegalArgumentException]
              step.tryNext shouldBe a[Failure[_]]
            }
          }
        }

        describe("11. Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Relying Party.") {
          it("Fails if RP ID is different.") {
            val steps = finishAssertion(
              rpId = Defaults.rpId.toBuilder.id("root.evil").build(),
              origins = Some(Set("https://localhost")),
            )
            val step: FinishAssertionSteps#Step11 =
              steps.begin.next.next.next.next.next.next.next.next.next.next.next

            step.validations shouldBe a[Failure[_]]
            step.validations.failed.get shouldBe an[IllegalArgumentException]
            step.tryNext shouldBe a[Failure[_]]
          }

          it("Succeeds if RP ID is the same.") {
            val steps = finishAssertion()
            val step: FinishAssertionSteps#Step11 =
              steps.begin.next.next.next.next.next.next.next.next.next.next.next

            step.validations shouldBe a[Success[_]]
            step.tryNext shouldBe a[Success[_]]
          }

          describe("When using the appid extension, it") {
            val appid = new AppId("https://test.example.org/foo")
            val extensions = AssertionExtensionInputs
              .builder()
              .appid(Some(appid).asJava)
              .build()

            it("fails if RP ID is different.") {
              val steps = finishAssertion(
                requestedExtensions = extensions,
                authenticatorData = new ByteArray(
                  Array.fill[Byte](32)(0) ++ Defaults.authenticatorData.getBytes
                    .drop(32)
                ),
              )
              val step: FinishAssertionSteps#Step11 =
                steps.begin.next.next.next.next.next.next.next.next.next.next.next

              step.validations shouldBe a[Failure[_]]
              step.validations.failed.get shouldBe an[IllegalArgumentException]
              step.tryNext shouldBe a[Failure[_]]
            }

            it("succeeds if RP ID is the SHA-256 hash of the standard RP ID.") {
              val steps = finishAssertion(requestedExtensions = extensions)
              val step: FinishAssertionSteps#Step11 =
                steps.begin.next.next.next.next.next.next.next.next.next.next.next

              step.validations shouldBe a[Success[_]]
              step.tryNext shouldBe a[Success[_]]
            }

            it("succeeds if RP ID is the SHA-256 hash of the appid.") {
              val steps = finishAssertion(
                requestedExtensions = extensions,
                authenticatorData = new ByteArray(
                  sha256(
                    appid.getId
                  ).getBytes ++ Defaults.authenticatorData.getBytes.drop(32)
                ),
              )
              val step: FinishAssertionSteps#Step11 =
                steps.begin.next.next.next.next.next.next.next.next.next.next.next

              step.validations shouldBe a[Success[_]]
              step.tryNext shouldBe a[Success[_]]
            }
          }
        }

        {
          def checks[Next <: FinishAssertionSteps.Step[
            _
          ], Step <: FinishAssertionSteps.Step[Next]](
              stepsToStep: FinishAssertionSteps => Step
          ) = {
            def check[Ret](stepsToStep: FinishAssertionSteps => Step)(
                chk: Step => Ret
            )(uvr: UserVerificationRequirement, authData: ByteArray): Ret = {
              val steps = finishAssertion(
                userVerificationRequirement = uvr,
                authenticatorData = authData,
              )
              chk(stepsToStep(steps))
            }
            def checkFailsWith(
                stepsToStep: FinishAssertionSteps => Step
            ): (UserVerificationRequirement, ByteArray) => Unit =
              check(stepsToStep) { step =>
                step.validations shouldBe a[Failure[_]]
                step.validations.failed.get shouldBe an[
                  IllegalArgumentException
                ]
                step.tryNext shouldBe a[Failure[_]]
              }
            def checkSucceedsWith(
                stepsToStep: FinishAssertionSteps => Step
            ): (UserVerificationRequirement, ByteArray) => Unit =
              check(stepsToStep) { step =>
                step.validations shouldBe a[Success[_]]
                step.tryNext shouldBe a[Success[_]]
              }

            (checkFailsWith(stepsToStep), checkSucceedsWith(stepsToStep))
          }

          describe("12. Verify that the User Present bit of the flags in authData is set.") {
            val flagOn: ByteArray = new ByteArray(
              Defaults.authenticatorData.getBytes.toVector
                .updated(
                  32,
                  (Defaults.authenticatorData.getBytes
                    .toVector(32) | 0x04 | 0x01).toByte,
                )
                .toArray
            )
            val flagOff: ByteArray = new ByteArray(
              Defaults.authenticatorData.getBytes.toVector
                .updated(
                  32,
                  ((Defaults.authenticatorData.getBytes
                    .toVector(32) | 0x04) & 0xfe).toByte,
                )
                .toArray
            )
            val (checkFails, checkSucceeds) =
              checks[FinishAssertionSteps#Step13, FinishAssertionSteps#Step12](
                _.begin.next.next.next.next.next.next.next.next.next.next.next.next
              )

            it("Fails if UV is discouraged and flag is not set.") {
              checkFails(UserVerificationRequirement.DISCOURAGED, flagOff)
            }

            it("Succeeds if UV is discouraged and flag is set.") {
              checkSucceeds(UserVerificationRequirement.DISCOURAGED, flagOn)
            }

            it("Fails if UV is preferred and flag is not set.") {
              checkFails(UserVerificationRequirement.PREFERRED, flagOff)
            }

            it("Succeeds if UV is preferred and flag is set.") {
              checkSucceeds(UserVerificationRequirement.PREFERRED, flagOn)
            }

            it("Fails if UV is required and flag is not set.") {
              checkFails(UserVerificationRequirement.REQUIRED, flagOff)
            }

            it("Succeeds if UV is required and flag is set.") {
              checkSucceeds(UserVerificationRequirement.REQUIRED, flagOn)
            }
          }

          describe("13. If user verification is required for this assertion, verify that the User Verified bit of the flags in authData is set.") {
            val flagOn: ByteArray = new ByteArray(
              Defaults.authenticatorData.getBytes.toVector
                .updated(
                  32,
                  (Defaults.authenticatorData.getBytes
                    .toVector(32) | 0x04).toByte,
                )
                .toArray
            )
            val flagOff: ByteArray = new ByteArray(
              Defaults.authenticatorData.getBytes.toVector
                .updated(
                  32,
                  (Defaults.authenticatorData.getBytes
                    .toVector(32) & 0xfb).toByte,
                )
                .toArray
            )
            val (checkFails, checkSucceeds) =
              checks[FinishAssertionSteps#Step14, FinishAssertionSteps#Step13](
                _.begin.next.next.next.next.next.next.next.next.next.next.next.next.next
              )

            it("Succeeds if UV is discouraged and flag is not set.") {
              checkSucceeds(UserVerificationRequirement.DISCOURAGED, flagOff)
            }

            it("Succeeds if UV is discouraged and flag is set.") {
              checkSucceeds(UserVerificationRequirement.DISCOURAGED, flagOn)
            }

            it("Succeeds if UV is preferred and flag is not set.") {
              checkSucceeds(UserVerificationRequirement.PREFERRED, flagOff)
            }

            it("Succeeds if UV is preferred and flag is set.") {
              checkSucceeds(UserVerificationRequirement.PREFERRED, flagOn)
            }

            it("Fails if UV is required and flag is not set.") {
              checkFails(UserVerificationRequirement.REQUIRED, flagOff)
            }

            it("Succeeds if UV is required and flag is set.") {
              checkSucceeds(UserVerificationRequirement.REQUIRED, flagOn)
            }
          }
        }

        describe("14. Verify that the values of the") {

          describe("client extension outputs in clientExtensionResults are as expected, considering the client extension input values that were given as the extensions option in the get() call. In particular, any extension identifier values in the clientExtensionResults MUST be also be present as extension identifier values in the extensions member of options, i.e., no extensions are present that were not requested. In the general case, the meaning of \"are as expected\" is specific to the Relying Party and which extensions are in use.") {
            it("Fails if clientExtensionResults is not a subset of the extensions requested by the Relying Party.") {

              forAll(Extensions.unrequestedClientAssertionExtensions) {
                case (extensionInputs, clientExtensionOutputs, _) =>
                  println(extensionInputs.getExtensionIds, extensionInputs)
                  println(
                    clientExtensionOutputs.getExtensionIds,
                    clientExtensionOutputs,
                  )

                  val steps = finishAssertion(
                    requestedExtensions = extensionInputs,
                    clientExtensionResults = clientExtensionOutputs,
                  )
                  val step: FinishAssertionSteps#Step14 =
                    steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next

                  step.validations shouldBe a[Failure[_]]
                  step.validations.failed.get shouldBe an[
                    IllegalArgumentException
                  ]
                  step.tryNext shouldBe a[Failure[_]]
              }
            }

            it("Succeeds if clientExtensionResults is not a subset of the extensions requested by the Relying Party, but the Relying Party has enabled allowing unrequested extensions.") {
              forAll(Extensions.unrequestedClientAssertionExtensions) {
                case (extensionInputs, clientExtensionOutputs, _) =>
                  println(extensionInputs.getExtensionIds, extensionInputs)
                  println(
                    clientExtensionOutputs.getExtensionIds,
                    clientExtensionOutputs,
                  )

                  val steps = finishAssertion(
                    allowUnrequestedExtensions = true,
                    requestedExtensions = extensionInputs,
                    clientExtensionResults = clientExtensionOutputs,
                  )
                  val step: FinishAssertionSteps#Step14 =
                    steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next

                  step.validations shouldBe a[Success[_]]
                  step.tryNext shouldBe a[Success[_]]
              }
            }

            it("Succeeds if clientExtensionResults is a subset of the extensions requested by the Relying Party.") {
              forAll(Extensions.subsetAssertionExtensions) {
                case (extensionInputs, clientExtensionOutputs, _) =>
                  println(extensionInputs.getExtensionIds, extensionInputs)
                  println(
                    clientExtensionOutputs.getExtensionIds,
                    clientExtensionOutputs,
                  )

                  val steps = finishAssertion(
                    requestedExtensions = extensionInputs,
                    clientExtensionResults = clientExtensionOutputs,
                  )
                  val step: FinishAssertionSteps#Step14 =
                    steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next

                  step.validations shouldBe a[Success[_]]
                  step.tryNext shouldBe a[Success[_]]
              }
            }
          }

          describe("authenticator extension outputs in the extensions in authData are as expected, considering the client extension input values that were given as the extensions option in the get() call. In particular, any extension identifier values in the extensions in authData MUST be also be present as extension identifier values in the extensions member of options, i.e., no extensions are present that were not requested. In the general case, the meaning of \"are as expected\" is specific to the Relying Party and which extensions are in use.") {
            it("Fails if authenticator extensions is not a subset of the extensions requested by the Relying Party.") {
              forAll(Extensions.unrequestedAuthenticatorAssertionExtensions) {
                case (
                      extensionInputs: AssertionExtensionInputs,
                      _,
                      authenticatorExtensionOutputs: CBORObject,
                    ) =>
                  println(extensionInputs)
                  println(authenticatorExtensionOutputs)

                  val steps = finishAssertion(
                    requestedExtensions = extensionInputs,
                    authenticatorData = TestAuthenticator.makeAuthDataBytes(
                      extensionsCborBytes = Some(
                        new ByteArray(
                          authenticatorExtensionOutputs.EncodeToBytes()
                        )
                      )
                    ),
                  )
                  val step: FinishAssertionSteps#Step14 =
                    steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next

                  step.validations shouldBe a[Failure[_]]
                  step.validations.failed.get shouldBe an[
                    IllegalArgumentException
                  ]
                  step.tryNext shouldBe a[Failure[_]]
              }
            }

            it("Succeeds if authenticator extensions is not a subset of the extensions requested by the Relying Party, but the Relying Party has enabled allowing unrequested extensions.") {
              forAll(Extensions.unrequestedAuthenticatorAssertionExtensions) {
                case (
                      extensionInputs: AssertionExtensionInputs,
                      _,
                      authenticatorExtensionOutputs: CBORObject,
                    ) =>
                  val steps = finishAssertion(
                    allowUnrequestedExtensions = true,
                    requestedExtensions = extensionInputs,
                    authenticatorData = TestAuthenticator.makeAuthDataBytes(
                      extensionsCborBytes = Some(
                        new ByteArray(
                          authenticatorExtensionOutputs.EncodeToBytes()
                        )
                      )
                    ),
                  )
                  val step: FinishAssertionSteps#Step14 =
                    steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next

                  step.validations shouldBe a[Success[_]]
                  step.tryNext shouldBe a[Success[_]]
              }
            }

            it("Succeeds if authenticator extensions is a subset of the extensions requested by the Relying Party.") {
              forAll(Extensions.subsetAssertionExtensions) {
                case (
                      extensionInputs: AssertionExtensionInputs,
                      _,
                      authenticatorExtensionOutputs: CBORObject,
                    ) =>
                  val steps = finishAssertion(
                    requestedExtensions = extensionInputs,
                    authenticatorData = TestAuthenticator.makeAuthDataBytes(
                      extensionsCborBytes = Some(
                        new ByteArray(
                          authenticatorExtensionOutputs.EncodeToBytes()
                        )
                      )
                    ),
                  )
                  val step: FinishAssertionSteps#Step14 =
                    steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next

                  step.validations shouldBe a[Success[_]]
                  step.tryNext shouldBe a[Success[_]]
              }
            }
          }

        }

        it("15. Let hash be the result of computing a hash over the cData using SHA-256.") {
          val steps = finishAssertion()
          val step: FinishAssertionSteps#Step15 =
            steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next

          step.validations shouldBe a[Success[_]]
          step.tryNext shouldBe a[Success[_]]
          step.clientDataJsonHash should equal(
            new ByteArray(
              MessageDigest
                .getInstance("SHA-256")
                .digest(Defaults.clientDataJsonBytes.getBytes)
            )
          )
        }

        describe("16. Using the credential public key looked up in step 3, verify that sig is a valid signature over the binary concatenation of authData and hash.") {
          it("The default test case succeeds.") {
            val steps = finishAssertion()
            val step: FinishAssertionSteps#Step16 =
              steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next

            step.validations shouldBe a[Success[_]]
            step.tryNext shouldBe a[Success[_]]
            step.signedBytes should not be null
          }

          it("A mutated clientDataJSON fails verification.") {
            val steps = finishAssertion(
              clientDataJson = JacksonCodecs.json.writeValueAsString(
                JacksonCodecs.json
                  .readTree(Defaults.clientDataJson)
                  .asInstanceOf[ObjectNode]
                  .set("foo", jsonFactory.textNode("bar"))
              )
            )
            val step: FinishAssertionSteps#Step16 =
              steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next

            step.validations shouldBe a[Failure[_]]
            step.validations.failed.get shouldBe an[IllegalArgumentException]
            step.tryNext shouldBe a[Failure[_]]
          }

          it("A test case with a different signed RP ID hash fails.") {
            val rpId = "ARGHABLARGHLER"
            val rpIdHash: ByteArray = Crypto.sha256(rpId)
            val steps = finishAssertion(
              authenticatorData = new ByteArray(
                (rpIdHash.getBytes.toVector ++ Defaults.authenticatorData.getBytes.toVector
                  .drop(32)).toArray
              ),
              rpId = Defaults.rpId.toBuilder.id(rpId).build(),
              origins = Some(Set("https://localhost")),
            )
            val step: FinishAssertionSteps#Step16 =
              steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next

            step.validations shouldBe a[Failure[_]]
            step.validations.failed.get shouldBe an[IllegalArgumentException]
            step.tryNext shouldBe a[Failure[_]]
          }

          it("A test case with a different signed flags field fails.") {
            val steps = finishAssertion(
              authenticatorData = new ByteArray(
                Defaults.authenticatorData.getBytes.toVector
                  .updated(
                    32,
                    (Defaults.authenticatorData.getBytes
                      .toVector(32) | 0x02).toByte,
                  )
                  .toArray
              )
            )
            val step: FinishAssertionSteps#Step16 =
              steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next

            step.validations shouldBe a[Failure[_]]
            step.validations.failed.get shouldBe an[IllegalArgumentException]
            step.tryNext shouldBe a[Failure[_]]
          }

          it("A test case with a different signed signature counter fails.") {
            val steps = finishAssertion(
              authenticatorData = new ByteArray(
                Defaults.authenticatorData.getBytes.toVector
                  .updated(33, 42.toByte)
                  .toArray
              )
            )
            val step: FinishAssertionSteps#Step16 =
              steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next

            step.validations shouldBe a[Failure[_]]
            step.validations.failed.get shouldBe an[IllegalArgumentException]
            step.tryNext shouldBe a[Failure[_]]
          }
        }

        describe("17. If the signature counter value authData.signCount is nonzero or the value stored in conjunction with credential’s id attribute is nonzero, then run the following sub-step:") {
          describe("If the signature counter value authData.signCount is") {
            def credentialRepository(signatureCount: Long) =
              Helpers.CredentialRepository.withUser(
                Defaults.user,
                RegisteredCredential
                  .builder()
                  .credentialId(Defaults.credentialId)
                  .userHandle(Defaults.userHandle)
                  .publicKeyCose(getPublicKeyBytes(Defaults.credentialKey))
                  .signatureCount(signatureCount)
                  .build(),
              )

            describe(
              "zero, then the stored signature counter value must also be zero."
            ) {
              val authenticatorData = new ByteArray(
                Defaults.authenticatorData.getBytes
                  .updated(33, 0: Byte)
                  .updated(34, 0: Byte)
                  .updated(35, 0: Byte)
                  .updated(36, 0: Byte)
              )
              val signature = TestAuthenticator.makeAssertionSignature(
                authenticatorData,
                Crypto.sha256(Defaults.clientDataJsonBytes),
                Defaults.credentialKey.getPrivate,
              )

              it("Succeeds if the stored signature counter value is zero.") {
                val cr = credentialRepository(0)
                val steps = finishAssertion(
                  authenticatorData = authenticatorData,
                  signature = signature,
                  credentialRepository = Some(cr),
                  validateSignatureCounter = true,
                )
                val step: FinishAssertionSteps#Step17 =
                  steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next

                step.validations shouldBe a[Success[_]]
                step.tryNext shouldBe a[Success[_]]
                step.next.result.get.isSignatureCounterValid should be(true)
                step.next.result.get.getSignatureCount should be(0)
              }

              it("Fails if the stored signature counter value is nonzero.") {
                val cr = credentialRepository(1)
                val steps = finishAssertion(
                  authenticatorData = authenticatorData,
                  signature = signature,
                  credentialRepository = Some(cr),
                  validateSignatureCounter = true,
                )
                val step: FinishAssertionSteps#Step17 =
                  steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next

                step.validations shouldBe a[Failure[_]]
                step.tryNext shouldBe a[Failure[_]]
                step.tryNext.failed.get shouldBe an[
                  InvalidSignatureCountException
                ]
              }
            }

            describe("greater than the signature counter value stored in conjunction with credential’s id attribute.") {
              val cr = credentialRepository(1336)

              describe("Update the stored signature counter value, associated with credential’s id attribute, to be the value of authData.signCount.") {
                it("An increasing signature counter always succeeds.") {
                  val steps = finishAssertion(
                    credentialRepository = Some(cr),
                    validateSignatureCounter = true,
                  )
                  val step: FinishAssertionSteps#Step17 =
                    steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next

                  step.validations shouldBe a[Success[_]]
                  step.tryNext shouldBe a[Success[_]]
                  step.next.result.get.isSignatureCounterValid should be(true)
                  step.next.result.get.getSignatureCount should be(1337)
                }
              }
            }

            describe("less than or equal to the signature counter value stored in conjunction with credential’s id attribute.") {
              val cr = credentialRepository(1337)

              describe("This is a signal that the authenticator may be cloned, i.e. at least two copies of the credential private key may exist and are being used in parallel. Relying Parties should incorporate this information into their risk scoring. Whether the Relying Party updates the stored signature counter value in this case, or not, or fails the authentication ceremony or not, is Relying Party-specific.") {
                it("If signature counter validation is disabled, a nonincreasing signature counter succeeds.") {
                  val steps = finishAssertion(
                    credentialRepository = Some(cr),
                    validateSignatureCounter = false,
                  )
                  val step: FinishAssertionSteps#Step17 =
                    steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next

                  step.validations shouldBe a[Success[_]]
                  step.tryNext shouldBe a[Success[_]]
                  step.next.result.get.isSignatureCounterValid should be(false)
                  step.next.result.get.getSignatureCount should be(1337)
                }

                it("If signature counter validation is enabled, a nonincreasing signature counter fails.") {
                  val steps = finishAssertion(
                    credentialRepository = Some(cr),
                    validateSignatureCounter = true,
                  )
                  val step: FinishAssertionSteps#Step17 =
                    steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next
                  val result = Try(step.run())

                  step.validations shouldBe a[Failure[_]]
                  step.validations.failed.get shouldBe an[
                    InvalidSignatureCountException
                  ]
                  step.tryNext shouldBe a[Failure[_]]

                  result shouldBe a[Failure[_]]
                  result.failed.get shouldBe an[InvalidSignatureCountException]
                  result.failed.get
                    .asInstanceOf[InvalidSignatureCountException]
                    .getExpectedMinimum should equal(1338)
                  result.failed.get
                    .asInstanceOf[InvalidSignatureCountException]
                    .getReceived should equal(1337)
                  result.failed.get
                    .asInstanceOf[InvalidSignatureCountException]
                    .getCredentialId should equal(Defaults.credentialId)
                }
              }
            }
          }
        }

        it("18. If all the above steps are successful, continue with the authentication ceremony as appropriate. Otherwise, fail the authentication ceremony.") {
          val steps = finishAssertion()
          val step: FinishAssertionSteps#Finished =
            steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next

          step.validations shouldBe a[Success[_]]
          Try(steps.run) shouldBe a[Success[_]]

          step.result.get.isSuccess should be(true)
          step.result.get.getCredentialId should equal(Defaults.credentialId)
          step.result.get.getUserHandle should equal(Defaults.userHandle)
        }

      }

    }

    describe("RelyingParty supports authenticating") {
      it("a real RSA key.") {
        val testData = RegistrationTestData.Packed.BasicAttestationRsaReal

        val credData =
          testData.response.getResponse.getAttestation.getAuthenticatorData.getAttestedCredentialData.get
        val credId: ByteArray = credData.getCredentialId
        val publicKeyBytes: ByteArray = credData.getCredentialPublicKey

        val request: AssertionRequest = AssertionRequest
          .builder()
          .publicKeyCredentialRequestOptions(
            JacksonCodecs.json.readValue(
              """{
              "challenge": "drdVqKT0T-9PyQfkceSE94Q8ruW2I-w1gsamBisjuMw",
              "rpId": "demo3.yubico.test",
              "userVerification": "preferred",
              "extensions": {
                "appid": "https://demo3.yubico.test:8443"
              }
            }""",
              classOf[PublicKeyCredentialRequestOptions],
            )
          )
          .username(testData.userId.getName)
          .build()

        val response: PublicKeyCredential[
          AuthenticatorAssertionResponse,
          ClientAssertionExtensionOutputs,
        ] = JacksonCodecs.json.readValue(
          """{
            "type": "public-key",
            "id": "ClvGfsNH8ulYnrKNd4fEgQ",
            "response": {
              "authenticatorData": "AU4Ai_91hLmkf2mxjxj_SJrA3qTIOjr6tw1rluqSp_4FAAAABA",
              "clientDataJSON": "ew0KCSJ0eXBlIiA6ICJ3ZWJhdXRobi5nZXQiLA0KCSJjaGFsbGVuZ2UiIDogImRyZFZxS1QwVC05UHlRZmtjZVNFOTRROHJ1VzJJLXcxZ3NhbUJpc2p1TXciLA0KCSJvcmlnaW4iIDogImh0dHBzOi8vZGVtbzMueXViaWNvLnRlc3Q6ODQ0MyIsDQoJInRva2VuQmluZGluZyIgOiANCgl7DQoJCSJzdGF0dXMiIDogInN1cHBvcnRlZCINCgl9DQp9",
              "signature": "1YYgnM1Nau6FQV2YK1qZDaoF6CHkFSxhaWac00dJNQemQueU_a1wE0hYy-g0O-ZwKn_MTtmfnwgjHxTRZx6v51eiuBpy-FlfkMmQHkz26MKKnQOK0Mc4kVjugvM0XlQ7E0hvsrdvVlmrwYc-U2IVfgRUw5rD-SbUctA_ZXc248LjyrgD_vhDWLR6I4nzmH_pe2tgKAQgohmzD4kVpVzS_T_M4Bn0Vcc5oUwNU4m57DiWDWCAR5BohKdajRgt8DUqBp9jvn9mgStIhEq1EIjhGdEE47WxVJaQb5IdHRaCNJ186x_ilsQvGT2Iy4s5C8IOkuffw07GesdpmJ8awtiA4A",
              "userHandle": "NiBJtVMh4AmSpZYuJ--jnEWgFzZHHVbS6zx7HFgAjAc"
            },
            "clientExtensionResults": {
              "appid": false
            }
          }""",
          new TypeReference[PublicKeyCredential[
            AuthenticatorAssertionResponse,
            ClientAssertionExtensionOutputs,
          ]]() {},
        )

        val credRepo = Helpers.CredentialRepository.withUser(
          testData.userId,
          RegisteredCredential
            .builder()
            .credentialId(testData.response.getId)
            .userHandle(testData.userId.getId)
            .publicKeyCose(publicKeyBytes)
            .build(),
        )

        val rp = RelyingParty
          .builder()
          .identity(
            RelyingPartyIdentity
              .builder()
              .id("demo3.yubico.test")
              .name("Yubico WebAuthn demo")
              .build()
          )
          .credentialRepository(credRepo)
          .origins(Set("https://demo3.yubico.test:8443").asJava)
          .build()

        val result = rp.finishAssertion(
          FinishAssertionOptions
            .builder()
            .request(request)
            .response(response)
            .build()
        )

        result.isSuccess should be(true)
        result.getUserHandle should equal(testData.userId.getId)
        result.getCredentialId should equal(credId)
      }

      it("an Ed25519 key.") {
        val registrationRequest = JacksonCodecs
          .json()
          .readValue(
            """
            |{
            |  "rp": {
            |    "name": "Yubico WebAuthn demo",
            |    "id": "demo3.yubico.test"
            |  },
            |  "user": {
            |    "name": "foo",
            |    "displayName": "Foo Bar",
            |    "id": "a2jHKZU9PDuGzwGaRQ5fVc8b_B3cfIOMZEiesm0Z-g0"
            |  },
            |  "challenge": "FFDZDypegliApKZXF8XCHCn2SlMy4BVupeOFXDSr1uE",
            |  "pubKeyCredParams": [
            |    {
            |      "alg": -8,
            |      "type": "public-key"
            |    }
            |  ],
            |  "excludeCredentials": [],
            |  "authenticatorSelection": {
            |    "requireResidentKey": false,
            |    "userVerification": "preferred"
            |  },
            |  "attestation": "direct",
            |  "extensions": {}
            |}
          """.stripMargin,
            classOf[PublicKeyCredentialCreationOptions],
          )
        val registrationResponse =
          PublicKeyCredential.parseRegistrationResponseJson("""
            |{
            |  "type": "public-key",
            |  "id": "PMEuc5FHylmDzH9BgG0lf_YqsOKKspino-b5ybq8CD0mpwU3Q4S4oUMQd_CgQsJOR3qyv3HirclQM2lNIiyi3dytZ6p-zbfBxDCH637qWTTZTZfKPxKBsdEOVPMBPopU_9uNXKh9dTxqe4mpSuznjxV-cEMF3BU3CSnJDU1BOCM",
            |  "response": {
            |    "attestationObject": "o2NmbXRmcGFja2VkaGF1dGhEYXRhWOEBTgCL_3WEuaR_abGPGP9ImsDepMg6Ovq3DWuW6pKn_kUAAAAC-KAR84wKTRWABhcRH57cfQCAPMEuc5FHylmDzH9BgG0lf_YqsOKKspino-b5ybq8CD0mpwU3Q4S4oUMQd_CgQsJOR3qyv3HirclQM2lNIiyi3dytZ6p-zbfBxDCH637qWTTZTZfKPxKBsdEOVPMBPopU_9uNXKh9dTxqe4mpSuznjxV-cEMF3BU3CSnJDU1BOCOkAQEDJyAGIVggSRLgxGS7m40dHlC9RGF4pzIj4V03KEVLj1iZ8-4zpgFnYXR0U3RtdKNjYWxnJmNzaWdYRzBFAiA6fyJf8gJc5N0fUJtpKckvc6jg0SJitLYVbzA3bl5uBgIhAI11DQDK7c0nhJGh5ElJzhTOcvvTovCAd31CZ_6ZsdrJY3g1Y4FZAmgwggJkMIIBTKADAgECAgQHL7bPMA0GCSqGSIb3DQEBCwUAMA8xDTALBgNVBAMMBHRlc3QwHhcNMTkwNDI0MTExMDAyWhcNMjAwNDIzMTExMDAyWjBuMQswCQYDVQQGEwJTRTESMBAGA1UECgwJWXViaWNvIEFCMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMScwJQYDVQQDDB5ZdWJpY28gVTJGIEVFIFNlcmlhbCAxMjA1Njc1MDMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATFcdVF_m2S3VTnMBABD0ZO8b4dvbqdr7a9zxLi9VBkR5YPakd2coJoFiuEcEuRhNJwSXlJlDX8q3Y-dY_Qp1XYozQwMjAiBgkrBgEEAYLECgIEFTEuMy42LjEuNC4xLjQxNDgyLjEuMjAMBgNVHRMBAf8EAjAAMA0GCSqGSIb3DQEBCwUAA4IBAQBm6U8jEfxKn5WqNe1r7LNlq80RVYQraj1V90Z-a1BFKEEDtRzmoNEGlaUVbmYrdv5u4lWd1abiSq7hWc4H7uTklC8wUt9F1qnSjDWkK45cYjwMpTtRavAQtX00R-8g1orIdSMAVsJ1RG-gqlvJhQWvlWQk8fHRBQ74MzVgUhutu74CgL8_-QjH1_2yEkAndj6slsTyNOCv2n60jJNzT9dk6oYE9HyvOuhYTc0IBAR5XsWQj1XXOof9CnARaC7C0P2Tn1yW0wjeP5St4i2aKuoL5tsaaSVk11hZ6XF2kjKjjqjow9uTyVIrn1NH-kwHf0cZSkPExkHLIl1JDtpMCE5R",
            |    "clientDataJSON": "ew0KCSJ0eXBlIiA6ICJ3ZWJhdXRobi5jcmVhdGUiLA0KCSJjaGFsbGVuZ2UiIDogIkZGRFpEeXBlZ2xpQXBLWlhGOFhDSENuMlNsTXk0QlZ1cGVPRlhEU3IxdUUiLA0KCSJvcmlnaW4iIDogImh0dHBzOi8vZGVtbzMueXViaWNvLnRlc3Q6ODQ0MyIsDQoJInRva2VuQmluZGluZyIgOiANCgl7DQoJCSJzdGF0dXMiIDogInN1cHBvcnRlZCINCgl9DQp9"
            |  },
            |  "clientExtensionResults": {}
            |}
            |
          """.stripMargin)

        val assertionRequest = JacksonCodecs
          .json()
          .readValue(
            """{
            |  "challenge": "YK17iD3fpOQKPSU6bxIU-TFBj1HNVSrX5bX5Pzj-SHQ",
            |  "rpId": "demo3.yubico.test",
            |  "allowCredentials": [
            |    {
            |      "type": "public-key",
            |      "id": "PMEuc5FHylmDzH9BgG0lf_YqsOKKspino-b5ybq8CD0mpwU3Q4S4oUMQd_CgQsJOR3qyv3HirclQM2lNIiyi3dytZ6p-zbfBxDCH637qWTTZTZfKPxKBsdEOVPMBPopU_9uNXKh9dTxqe4mpSuznjxV-cEMF3BU3CSnJDU1BOCM"
            |    }
            |  ],
            |  "userVerification": "preferred",
            |  "extensions": {
            |    "appid": "https://demo3.yubico.test:8443"
            |  }
            |}
            |""".stripMargin,
            classOf[PublicKeyCredentialRequestOptions],
          )
        val assertionResponse = PublicKeyCredential.parseAssertionResponseJson(
          """
            |{
            |  "type": "public-key",
            |  "id": "PMEuc5FHylmDzH9BgG0lf_YqsOKKspino-b5ybq8CD0mpwU3Q4S4oUMQd_CgQsJOR3qyv3HirclQM2lNIiyi3dytZ6p-zbfBxDCH637qWTTZTZfKPxKBsdEOVPMBPopU_9uNXKh9dTxqe4mpSuznjxV-cEMF3BU3CSnJDU1BOCM",
            |  "response": {
            |    "authenticatorData": "AU4Ai_91hLmkf2mxjxj_SJrA3qTIOjr6tw1rluqSp_4FAAAACA",
            |    "clientDataJSON": "ew0KCSJ0eXBlIiA6ICJ3ZWJhdXRobi5nZXQiLA0KCSJjaGFsbGVuZ2UiIDogIllLMTdpRDNmcE9RS1BTVTZieElVLVRGQmoxSE5WU3JYNWJYNVB6ai1TSFEiLA0KCSJvcmlnaW4iIDogImh0dHBzOi8vZGVtbzMueXViaWNvLnRlc3Q6ODQ0MyIsDQoJInRva2VuQmluZGluZyIgOiANCgl7DQoJCSJzdGF0dXMiIDogInN1cHBvcnRlZCINCgl9DQp9",
            |    "signature": "YWVfTS-0-j6mRFG_fYBN9ApkhgjH89hyOVGaOuqxazXv1jA3YBQjoTurN43PebHPXDC6gNxjATUGxMvCq2t5Dg",
            |    "userHandle": null
            |  },
            |  "clientExtensionResults": {
            |    "appid": false
            |  }
            |}
          """.stripMargin
        )

        val credData =
          registrationResponse.getResponse.getAttestation.getAuthenticatorData.getAttestedCredentialData.get
        val credId: ByteArray = credData.getCredentialId
        val publicKeyBytes: ByteArray = credData.getCredentialPublicKey

        val credRepo = Helpers.CredentialRepository.withUser(
          registrationRequest.getUser,
          RegisteredCredential
            .builder()
            .credentialId(registrationResponse.getId)
            .userHandle(registrationRequest.getUser.getId)
            .publicKeyCose(publicKeyBytes)
            .build(),
        )

        val rp = RelyingParty
          .builder()
          .identity(
            RelyingPartyIdentity
              .builder()
              .id("demo3.yubico.test")
              .name("Yubico WebAuthn demo")
              .build()
          )
          .credentialRepository(credRepo)
          .origins(Set("https://demo3.yubico.test:8443").asJava)
          .build()

        val result = rp.finishAssertion(
          FinishAssertionOptions
            .builder()
            .request(
              AssertionRequest
                .builder()
                .publicKeyCredentialRequestOptions(assertionRequest)
                .username(registrationRequest.getUser.getName)
                .build()
            )
            .response(assertionResponse)
            .build()
        )

        result.isSuccess should be(true)
        result.getUserHandle should equal(registrationRequest.getUser.getId)
        result.getCredentialId should equal(credId)
      }

      it("a generated Ed25519 key.") {
        val registrationTestData =
          RegistrationTestData.Packed.BasicAttestationEdDsa
        val testData = registrationTestData.assertion.get

        val rp = RelyingParty
          .builder()
          .identity(
            RelyingPartyIdentity.builder().id("localhost").name("Test RP").build()
          )
          .credentialRepository(
            Helpers.CredentialRepository.withUser(
              registrationTestData.userId,
              RegisteredCredential
                .builder()
                .credentialId(registrationTestData.response.getId)
                .userHandle(registrationTestData.userId.getId)
                .publicKeyCose(
                  registrationTestData.response.getResponse.getParsedAuthenticatorData.getAttestedCredentialData.get.getCredentialPublicKey
                )
                .signatureCount(0)
                .build(),
            )
          )
          .build()

        val result = rp.finishAssertion(
          FinishAssertionOptions
            .builder()
            .request(testData.request)
            .response(testData.response)
            .build()
        )

        result.isSuccess should be(true)
        result.getUserHandle should equal(registrationTestData.userId.getId)
        result.getCredentialId should equal(registrationTestData.response.getId)
        result.getCredentialId should equal(testData.response.getId)
      }

      describe("an RS1 key") {
        def test(registrationTestData: RegistrationTestData): Unit = {
          val testData = registrationTestData.assertion.get

          val rp = RelyingParty
            .builder()
            .identity(
              RelyingPartyIdentity
                .builder()
                .id("localhost")
                .name("Test RP")
                .build()
            )
            .credentialRepository(
              Helpers.CredentialRepository.withUser(
                registrationTestData.userId,
                RegisteredCredential
                  .builder()
                  .credentialId(registrationTestData.response.getId)
                  .userHandle(registrationTestData.userId.getId)
                  .publicKeyCose(
                    registrationTestData.response.getResponse.getParsedAuthenticatorData.getAttestedCredentialData.get.getCredentialPublicKey
                  )
                  .signatureCount(0)
                  .build(),
              )
            )
            .build()

          val result = rp.finishAssertion(
            FinishAssertionOptions
              .builder()
              .request(testData.request)
              .response(testData.response)
              .build()
          )

          result.isSuccess should be(true)
          result.getUserHandle should equal(registrationTestData.userId.getId)
          result.getCredentialId should equal(
            registrationTestData.response.getId
          )
          result.getCredentialId should equal(testData.response.getId)
        }

        it("with basic attestation.") {
          test(RegistrationTestData.Packed.BasicAttestationRs1)
        }
        it("with self attestation.") {
          test(RegistrationTestData.Packed.SelfAttestationRs1)
        }
      }
    }

    describe("The default RelyingParty settings") {
      val testDataBase = RegistrationTestData.Packed.BasicAttestationEdDsa
      val rp = RelyingParty
        .builder()
        .identity(testDataBase.rpId)
        .credentialRepository(
          Helpers.CredentialRepository.withUser(
            testDataBase.userId,
            RegisteredCredential
              .builder()
              .credentialId(testDataBase.response.getId)
              .userHandle(testDataBase.userId.getId)
              .publicKeyCose(
                testDataBase.response.getResponse.getParsedAuthenticatorData.getAttestedCredentialData.get.getCredentialPublicKey
              )
              .build(),
          )
        )
        .build()

      describe("support the largeBlob extension") {
        it("for writing a blob.") {
          val result = rp.finishAssertion(
            FinishAssertionOptions
              .builder()
              .request(
                testDataBase.assertion.get.request.toBuilder
                  .publicKeyCredentialRequestOptions(
                    testDataBase.assertion.get.request.getPublicKeyCredentialRequestOptions.toBuilder
                      .extensions(
                        AssertionExtensionInputs
                          .builder()
                          .largeBlob(
                            LargeBlobAuthenticationInput
                              .write(ByteArray.fromHex("00010203"))
                          )
                          .build()
                      )
                      .build()
                  )
                  .build()
              )
              .response(
                testDataBase.assertion.get.response.toBuilder
                  .clientExtensionResults(
                    ClientAssertionExtensionOutputs
                      .builder()
                      .largeBlob(
                        ReexportHelpers
                          .newLargeBlobAuthenticationOutput(None, Some(true))
                      )
                      .build()
                  )
                  .build()
              )
              .build()
          )

          result.getClientExtensionOutputs.get.getLargeBlob.get.getWritten.asScala should be(
            Some(true)
          )
          result.getClientExtensionOutputs.get.getLargeBlob.get.getBlob.asScala should be(
            None
          )
        }

        it("for reading a blob.") {
          val result = rp.finishAssertion(
            FinishAssertionOptions
              .builder()
              .request(
                testDataBase.assertion.get.request.toBuilder
                  .publicKeyCredentialRequestOptions(
                    testDataBase.assertion.get.request.getPublicKeyCredentialRequestOptions.toBuilder
                      .extensions(
                        AssertionExtensionInputs
                          .builder()
                          .largeBlob(LargeBlobAuthenticationInput.read())
                          .build()
                      )
                      .build()
                  )
                  .build()
              )
              .response(
                testDataBase.assertion.get.response.toBuilder
                  .clientExtensionResults(
                    ClientAssertionExtensionOutputs
                      .builder()
                      .largeBlob(
                        ReexportHelpers.newLargeBlobAuthenticationOutput(
                          Some(ByteArray.fromHex("00010203")),
                          None,
                        )
                      )
                      .build()
                  )
                  .build()
              )
              .build()
          )

          result.getClientExtensionOutputs.get.getLargeBlob.get.getBlob.asScala should be(
            Some(ByteArray.fromHex("00010203"))
          )
          result.getClientExtensionOutputs.get.getLargeBlob.get.getWritten.asScala should be(
            None
          )
        }
      }

      describe("support the uvm extension") {
        it("at authentication time.") {

          // Example from spec: https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-uvm-extension
          // A1                     -- extension: CBOR map of one element
          //     63                 -- Key 1: CBOR text string of 3 bytes
          //         75 76 6d       -- "uvm" [=UTF-8 encoded=] string
          //     82                 -- Value 1: CBOR array of length 2 indicating two factor usage
          //         83              -- Item 1: CBOR array of length 3
          //             02           -- Subitem 1: CBOR integer for User Verification Method Fingerprint
          //             04           -- Subitem 2: CBOR short for Key Protection Type TEE
          //             02           -- Subitem 3: CBOR short for Matcher Protection Type TEE
          //         83              -- Item 2: CBOR array of length 3
          //             04           -- Subitem 1: CBOR integer for User Verification Method Passcode
          //             01           -- Subitem 2: CBOR short for Key Protection Type Software
          //             01           -- Subitem 3: CBOR short for Matcher Protection Type Software
          val uvmCborExample = ByteArray.fromHex("A16375766d828302040283040101")

          val cred = TestAuthenticator.createAssertionFromTestData(
            testDataBase,
            testDataBase.assertion.get.request.getPublicKeyCredentialRequestOptions,
            authenticatorExtensions =
              Some(JacksonCodecs.cbor().readTree(uvmCborExample.getBytes)),
          )

          val result = rp.finishAssertion(
            FinishAssertionOptions
              .builder()
              .request(
                testDataBase.assertion.get.request.toBuilder
                  .publicKeyCredentialRequestOptions(
                    testDataBase.assertion.get.request.getPublicKeyCredentialRequestOptions.toBuilder
                      .extensions(
                        AssertionExtensionInputs
                          .builder()
                          .uvm()
                          .build()
                      )
                      .build()
                  )
                  .build()
              )
              .response(cred)
              .build()
          )

          result.getAuthenticatorExtensionOutputs.get.getUvm.asScala should equal(
            Some(
              List(
                new UvmEntry(
                  UserVerificationMethod.USER_VERIFY_FINGERPRINT_INTERNAL,
                  KeyProtectionType.KEY_PROTECTION_TEE,
                  MatcherProtectionType.MATCHER_PROTECTION_TEE,
                ),
                new UvmEntry(
                  UserVerificationMethod.USER_VERIFY_PASSCODE_INTERNAL,
                  KeyProtectionType.KEY_PROTECTION_SOFTWARE,
                  MatcherProtectionType.MATCHER_PROTECTION_SOFTWARE,
                ),
              ).asJava
            )
          )
        }
      }
    }
  }

}
