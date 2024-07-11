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
import com.fasterxml.jackson.databind.node.TextNode
import com.upokecenter.cbor.CBORObject
import com.yubico.internal.util.JacksonCodecs
import com.yubico.webauthn.data.AssertionExtensionInputs
import com.yubico.webauthn.data.AuthenticatorAssertionResponse
import com.yubico.webauthn.data.AuthenticatorAttachment
import com.yubico.webauthn.data.AuthenticatorDataFlags
import com.yubico.webauthn.data.AuthenticatorTransport
import com.yubico.webauthn.data.ByteArray
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs
import com.yubico.webauthn.data.CollectedClientData
import com.yubico.webauthn.data.Extensions.CredentialProperties.CredentialPropertiesOutput
import com.yubico.webauthn.data.Extensions.LargeBlob.LargeBlobAuthenticationInput
import com.yubico.webauthn.data.Extensions.LargeBlob.LargeBlobAuthenticationOutput
import com.yubico.webauthn.data.Extensions.Uvm.UvmEntry
import com.yubico.webauthn.data.Generators._
import com.yubico.webauthn.data.PublicKeyCredential
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor
import com.yubico.webauthn.data.PublicKeyCredentialParameters
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions
import com.yubico.webauthn.data.RelyingPartyIdentity
import com.yubico.webauthn.data.UserIdentity
import com.yubico.webauthn.data.UserVerificationRequirement
import com.yubico.webauthn.exception.InvalidSignatureCountException
import com.yubico.webauthn.extension.appid.AppId
import com.yubico.webauthn.extension.uvm.KeyProtectionType
import com.yubico.webauthn.extension.uvm.MatcherProtectionType
import com.yubico.webauthn.extension.uvm.UserVerificationMethod
import com.yubico.webauthn.test.Helpers
import com.yubico.webauthn.test.RealExamples
import com.yubico.webauthn.test.Util.toStepWithUtilities
import org.junit.runner.RunWith
import org.scalacheck.Arbitrary.arbitrary
import org.scalacheck.Gen
import org.scalatest.funspec.AnyFunSpec
import org.scalatest.matchers.should.Matchers
import org.scalatestplus.junit.JUnitRunner
import org.scalatestplus.scalacheck.ScalaCheckDrivenPropertyChecks

import java.io.IOException
import java.nio.charset.Charset
import java.security.KeyPair
import java.security.MessageDigest
import java.security.interfaces.ECPublicKey
import java.util.Optional
import scala.jdk.CollectionConverters._
import scala.jdk.OptionConverters.RichOption
import scala.jdk.OptionConverters.RichOptional
import scala.util.Failure
import scala.util.Success
import scala.util.Try

@RunWith(classOf[JUnitRunner])
class RelyingPartyAssertionSpec
    extends AnyFunSpec
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
      Some(userHandle).toJava
    else
      ???

  private def getUsernameIfDefaultUserHandle(
      userHandle: ByteArray,
      username: String,
  ): Optional[String] =
    if (userHandle == Defaults.userHandle)
      Some(username).toJava
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
      authenticatorData: ByteArray = Defaults.authenticatorData,
      callerTokenBindingId: Option[ByteArray] = None,
      challenge: ByteArray = Defaults.challenge,
      clientDataJson: String = Defaults.clientDataJson,
      clientExtensionResults: ClientAssertionExtensionOutputs =
        Defaults.clientExtensionResults,
      credentialId: ByteArray = Defaults.credentialId,
      credentialKey: KeyPair = Defaults.credentialKey,
      credentialRepository: Option[CredentialRepository] = None,
      isSecurePaymentConfirmation: Option[Boolean] = None,
      origins: Option[Set[String]] = None,
      requestedExtensions: AssertionExtensionInputs =
        Defaults.requestedExtensions,
      rpId: RelyingPartyIdentity = Defaults.rpId,
      signature: ByteArray = Defaults.signature,
      userHandleForResponse: Option[ByteArray] = Some(Defaults.userHandle),
      userHandleForRequest: Option[ByteArray] = None,
      userHandleForUser: ByteArray = Defaults.userHandle,
      usernameForRequest: Option[String] = Some(Defaults.username),
      usernameForUser: String = Defaults.username,
      userVerificationRequirement: UserVerificationRequirement =
        UserVerificationRequirement.PREFERRED,
      validateSignatureCounter: Boolean = true,
  ): FinishAssertionSteps[RegisteredCredential] = {
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
          .allowCredentials(allowCredentials.toJava)
          .userVerification(userVerificationRequirement)
          .extensions(requestedExtensions)
          .build()
      )
      .username(usernameForRequest.toJava)
      .userHandle(userHandleForRequest.toJava)
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
          .userHandle(userHandleForResponse.toJava)
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
            ).toJava
          override def lookupAll(credId: ByteArray) =
            lookup(credId, null).toScala.toSet.asJava
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
      .validateSignatureCounter(validateSignatureCounter)

    origins.map(_.asJava).foreach(builder.origins _)

    val fao = FinishAssertionOptions
      .builder()
      .request(request)
      .response(response)
      .callerTokenBindingId(callerTokenBindingId.toJava)

    isSecurePaymentConfirmation foreach { isSpc =>
      fao.isSecurePaymentConfirmation(isSpc)
    }

    builder
      .build()
      ._finishAssertion(fao.build())
  }

  testWithEachProvider { it =>
    describe("RelyingParty.startAssertion") {

      describe(
        "respects the userVerification parameter in StartAssertionOptions."
      ) {
        it(s"If the parameter is not set, or set to empty, it is also empty in the result.") {
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

          request1.getPublicKeyCredentialRequestOptions.getUserVerification.toScala should be(
            None
          )
          request2.getPublicKeyCredentialRequestOptions.getUserVerification.toScala should be(
            None
          )
        }

        it(s"If the parameter is set, that value is used.") {
          val rp = RelyingParty
            .builder()
            .identity(Defaults.rpId)
            .credentialRepository(Helpers.CredentialRepository.empty)
            .build()

          forAll { uv: Option[UserVerificationRequirement] =>
            val request = rp.startAssertion(
              StartAssertionOptions
                .builder()
                .userVerification(uv.toJava)
                .build()
            )

            request.getPublicKeyCredentialRequestOptions.getUserVerification.toScala should equal(
              uv
            )
          }
        }
      }

    }

    describe("RelyingParty.finishAssertion") {

      it("does not make redundant calls to CredentialRepository.lookup().") {
        val registrationTestData =
          RegistrationTestData.Packed.BasicAttestationEdDsa
        val testData = registrationTestData.assertion.get

        val credRepo = {
          val user = registrationTestData.userId
          val credential = RegisteredCredential
            .builder()
            .credentialId(registrationTestData.response.getId)
            .userHandle(registrationTestData.userId.getId)
            .publicKeyCose(
              registrationTestData.response.getResponse.getParsedAuthenticatorData.getAttestedCredentialData.get.getCredentialPublicKey
            )
            .signatureCount(0)
            .build()

          new CredentialRepository {
            var lookupCount = 0

            override def getCredentialIdsForUsername(
                username: String
            ): java.util.Set[PublicKeyCredentialDescriptor] =
              if (username == user.getName)
                Set(
                  PublicKeyCredentialDescriptor
                    .builder()
                    .id(credential.getCredentialId)
                    .build()
                ).asJava
              else Set.empty.asJava

            override def getUserHandleForUsername(
                username: String
            ): Optional[ByteArray] =
              if (username == user.getName)
                Some(user.getId).toJava
              else None.toJava

            override def getUsernameForUserHandle(
                userHandle: ByteArray
            ): Optional[String] =
              if (userHandle == user.getId)
                Some(user.getName).toJava
              else None.toJava

            override def lookup(
                credentialId: ByteArray,
                userHandle: ByteArray,
            ): Optional[RegisteredCredential] = {
              lookupCount += 1
              if (
                credentialId == credential.getCredentialId && userHandle == user.getId
              )
                Some(credential).toJava
              else None.toJava
            }

            override def lookupAll(
                credentialId: ByteArray
            ): java.util.Set[RegisteredCredential] =
              if (credentialId == credential.getCredentialId)
                Set(credential).asJava
              else Set.empty.asJava
          }
        }
        val rp = RelyingParty
          .builder()
          .identity(
            RelyingPartyIdentity.builder().id("localhost").name("Test RP").build()
          )
          .credentialRepository(credRepo)
          .build()

        val result = rp.finishAssertion(
          FinishAssertionOptions
            .builder()
            .request(testData.request)
            .response(testData.response)
            .build()
        )

        result.isSuccess should be(true)
        result.getCredential.getUserHandle should equal(
          registrationTestData.userId.getId
        )
        result.getCredential.getCredentialId should equal(
          registrationTestData.response.getId
        )
        result.getCredential.getCredentialId should equal(
          testData.response.getId
        )
        credRepo.lookupCount should equal(1)
      }

      describe("§7.2. Verifying an authentication assertion: When verifying a given PublicKeyCredential structure (credential) and an AuthenticationExtensionsClientOutputs structure clientExtensionResults, as part of an authentication ceremony, the Relying Party MUST proceed as follows:") {

        describe("1. Let options be a new PublicKeyCredentialRequestOptions structure configured to the Relying Party's needs for the ceremony.") {
          it("If options.allowCredentials is present, the transports member of each item SHOULD be set to the value returned by credential.response.getTransports() when the corresponding credential was registered.") {
            forAll(
              Gen.nonEmptyContainerOf[Set, AuthenticatorTransport](
                arbitrary[AuthenticatorTransport]
              ),
              arbitrary[PublicKeyCredentialDescriptor],
              arbitrary[PublicKeyCredentialDescriptor],
              arbitrary[PublicKeyCredentialDescriptor],
            ) {
              (
                  cred1Transports: Set[AuthenticatorTransport],
                  cred1: PublicKeyCredentialDescriptor,
                  cred2: PublicKeyCredentialDescriptor,
                  cred3: PublicKeyCredentialDescriptor,
              ) =>
                val rp = RelyingParty
                  .builder()
                  .identity(Defaults.rpId)
                  .credentialRepository(new CredentialRepository {
                    override def getCredentialIdsForUsername(
                        username: String
                    ): java.util.Set[PublicKeyCredentialDescriptor] =
                      Set(
                        cred1.toBuilder
                          .transports(cred1Transports.asJava)
                          .build(),
                        cred2.toBuilder
                          .transports(
                            Optional.of(
                              Set.empty[AuthenticatorTransport].asJava
                            )
                          )
                          .build(),
                        cred3.toBuilder
                          .transports(
                            Optional
                              .empty[java.util.Set[AuthenticatorTransport]]
                          )
                          .build(),
                      ).asJava
                    override def getUserHandleForUsername(
                        username: String
                    ): Optional[ByteArray] = ???
                    override def getUsernameForUserHandle(
                        userHandleBase64: ByteArray
                    ): Optional[String] = ???
                    override def lookup(
                        credentialId: ByteArray,
                        userHandle: ByteArray,
                    ): Optional[RegisteredCredential] = ???
                    override def lookupAll(
                        credentialId: ByteArray
                    ): java.util.Set[RegisteredCredential] = ???
                  })
                  .preferredPubkeyParams(
                    List(PublicKeyCredentialParameters.ES256).asJava
                  )
                  .build()

                val result = rp.startAssertion(
                  StartAssertionOptions
                    .builder()
                    .username(Defaults.username)
                    .build()
                )

                val requestCreds =
                  result.getPublicKeyCredentialRequestOptions.getAllowCredentials.get.asScala
                requestCreds.head.getTransports.toScala should equal(
                  Some(cred1Transports.asJava)
                )
                requestCreds(1).getTransports.toScala should equal(
                  Some(Set.empty.asJava)
                )
                requestCreds(2).getTransports.toScala should equal(None)
            }
          }
        }

        describe("2. Call navigator.credentials.get() and pass options as the publicKey option. Let credential be the result of the successfully resolved promise. If the promise is rejected, abort the ceremony with a user-visible error, or otherwise guide the user experience as might be determinable from the context available in the rejected promise. For information on different error contexts and the circumstances leading to them, see § 6.3.3 The authenticatorGetAssertion Operation.") {
          it("Nothing to test: applicable only to client side.") {}
        }

        it("3. Let response be credential.response. If response is not an instance of AuthenticatorAssertionResponse, abort the ceremony with a user-visible error.") {
          val testData =
            RegistrationTestData.Packed.BasicAttestationEdDsa.assertion.get
          val faob = FinishAssertionOptions
            .builder()
            .request(testData.request)
          "faob.response(testData.request)" shouldNot compile
          faob.response(testData.response).build() should not be null
        }

        describe("4. Let clientExtensionResults be the result of calling credential.getClientExtensionResults().") {
          it(
            "The PublicKeyCredential class has a clientExtensionResults field"
          ) {
            val pkc = PublicKeyCredential.parseAssertionResponseJson("""{
                "type": "public-key",
                "id": "",
                "response": {
                  "authenticatorData": "xGzvgq0bVGR3WR0Aiwh1nsPm0uy085R0v-ppaZJdA7cBAAAABQ",
                  "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiaHZGN1AxNGwxTjZUcEhnZXVBMjhDdnJaTE1yVjRSMjdZd2JrY2FSYlRPZyIsIm9yaWdpbiI6Imh0dHBzOi8vZGVtby55dWJpY28uY29tIiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ==",
                  "signature": "MEYCIQCi7u0ErVIGZIWOQbc_y7IYcNXBniczTgzHH_yE0WfzcQIhALDsITBJDPQMBFxB6pKd608lRVPcNeNnrX3olAxA3AmX"
                },
                "clientExtensionResults": {
                  "appid": true,
                  "org.example.foo": "bar"
                }
              }""")
            pkc.getClientExtensionResults.getExtensionIds should contain(
              "appid"
            )
          }
        }

        describe("5. If options.allowCredentials is not empty, verify that credential.id identifies one of the public key credentials listed in options.allowCredentials.") {
          it("Fails if returned credential ID is not a requested one.") {
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
            val step: FinishAssertionSteps[RegisteredCredential]#Step5 =
              steps.begin

            step.validations shouldBe a[Failure[_]]
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
            val step: FinishAssertionSteps[RegisteredCredential]#Step5 =
              steps.begin

            step.validations shouldBe a[Success[_]]
            step.tryNext shouldBe a[Success[_]]
          }

          it("Succeeds if no credential IDs were requested.") {
            for {
              allowCredentials <- List(
                None,
                Some(List.empty[PublicKeyCredentialDescriptor].asJava),
              )
            } {
              val steps = finishAssertion(
                allowCredentials = allowCredentials,
                credentialId = new ByteArray(Array(0, 1, 2, 3)),
              )
              val step: FinishAssertionSteps[RegisteredCredential]#Step5 =
                steps.begin

              step.validations shouldBe a[Success[_]]
              step.tryNext shouldBe a[Success[_]]
            }
          }
        }

        describe("6. Identify the user being authenticated and verify that this user is the owner of the public key credential source credentialSource identified by credential.id:") {
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
              ).toJava
            override def lookupAll(id: ByteArray) = ???
            override def getCredentialIdsForUsername(username: String) = ???
            override def getUserHandleForUsername(
                username: String
            ): Optional[ByteArray] =
              Some(
                if (username == owner.username) owner.userHandle
                else nonOwner.userHandle
              ).toJava
            override def getUsernameForUserHandle(
                userHandle: ByteArray
            ): Optional[String] =
              Some(
                if (userHandle == owner.userHandle) owner.username
                else nonOwner.username
              ).toJava
          })

          describe("If the user was identified before the authentication ceremony was initiated, e.g., via a username or cookie, verify that the identified user is the owner of credentialSource. If response.userHandle is present, let userHandle be its value. Verify that userHandle also maps to the same user.") {
            it(
              "Fails if credential ID is not owned by the given user handle."
            ) {
              val steps = finishAssertion(
                credentialRepository = credentialRepository,
                userHandleForResponse = Some(nonOwner.userHandle),
                userHandleForUser = owner.userHandle,
                usernameForRequest = Some(owner.username),
              )
              val step: FinishAssertionSteps[RegisteredCredential]#Step6 =
                steps.begin.next

              step.validations shouldBe a[Failure[_]]
              step.validations.failed.get shouldBe an[IllegalArgumentException]
              step.tryNext shouldBe a[Failure[_]]
            }

            it(
              "Fails if response.userHandle does not identify the same user as request.username."
            ) {
              val steps = finishAssertion(
                credentialRepository = credentialRepository,
                usernameForRequest = Some(nonOwner.username),
                userHandleForUser = owner.userHandle,
                userHandleForResponse = Some(owner.userHandle),
              )
              val step: FinishAssertionSteps[RegisteredCredential]#Step6 =
                steps.begin.next

              step.validations shouldBe a[Failure[_]]
              step.validations.failed.get shouldBe an[IllegalArgumentException]
              step.tryNext shouldBe a[Failure[_]]
            }

            it("Succeeds if credential ID is owned by the given user handle.") {
              val steps = finishAssertion(
                credentialRepository = credentialRepository,
                userHandleForResponse = Some(owner.userHandle),
                userHandleForUser = owner.userHandle,
                usernameForRequest = Some(owner.username),
              )
              val step: FinishAssertionSteps[RegisteredCredential]#Step6 =
                steps.begin.next

              step.validations shouldBe a[Success[_]]
              step.tryNext shouldBe a[Success[_]]
            }
          }

          describe("If the user was not identified before the authentication ceremony was initiated, verify that response.userHandle is present, and that the user identified by this value is the owner of credentialSource.") {
            it(
              "Fails if response.userHandle is not present."
            ) {
              val steps = finishAssertion(
                credentialRepository = credentialRepository,
                usernameForRequest = None,
                userHandleForUser = owner.userHandle,
                userHandleForResponse = None,
              )
              val step: FinishAssertionSteps[RegisteredCredential]#Step6 =
                steps.begin.next

              step.validations shouldBe a[Failure[_]]
              step.validations.failed.get shouldBe an[IllegalArgumentException]
              step.tryNext shouldBe a[Failure[_]]
            }

            it(
              "Fails if credential ID is not owned by the user handle in the response."
            ) {
              val steps = finishAssertion(
                credentialRepository = credentialRepository,
                userHandleForResponse = Some(nonOwner.userHandle),
                userHandleForUser = owner.userHandle,
                usernameForRequest = None,
              )
              val step: FinishAssertionSteps[RegisteredCredential]#Step6 =
                steps.begin.next

              step.validations shouldBe a[Failure[_]]
              step.validations.failed.get shouldBe an[IllegalArgumentException]
              step.tryNext shouldBe a[Failure[_]]
            }

            it(
              "Fails if credential ID is not owned by the user handle in the request."
            ) {
              val steps = finishAssertion(
                credentialRepository = credentialRepository,
                userHandleForRequest = Some(nonOwner.userHandle),
                userHandleForResponse = None,
                userHandleForUser = owner.userHandle,
                usernameForRequest = None,
              )
              val step: FinishAssertionSteps[RegisteredCredential]#Step6 =
                steps.begin.next

              step.validations shouldBe a[Failure[_]]
              step.validations.failed.get shouldBe an[IllegalArgumentException]
              step.tryNext shouldBe a[Failure[_]]
            }

            it("Fails if neither username nor user handle is given.") {
              val steps = finishAssertion(
                credentialRepository = credentialRepository,
                userHandleForRequest = None,
                userHandleForResponse = None,
                userHandleForUser = owner.userHandle,
                usernameForRequest = None,
              )
              val step: FinishAssertionSteps[RegisteredCredential]#Step6 =
                steps.begin.next

              step.validations shouldBe a[Failure[_]]
              step.validations.failed.get shouldBe an[IllegalArgumentException]
              step.tryNext shouldBe a[Failure[_]]
            }

            it("Fails if user handle in request does not agree with user handle in response.") {
              val steps = finishAssertion(
                credentialRepository = credentialRepository,
                userHandleForRequest = Some(owner.userHandle),
                userHandleForResponse = Some(nonOwner.userHandle),
                userHandleForUser = owner.userHandle,
                usernameForRequest = None,
              )
              val step: FinishAssertionSteps[RegisteredCredential]#Step6 =
                steps.begin.next

              step.validations shouldBe a[Failure[_]]
              step.validations.failed.get shouldBe an[IllegalArgumentException]
              step.tryNext shouldBe a[Failure[_]]
            }

            it("Succeeds if credential ID is owned by the user handle in the response.") {
              val steps = finishAssertion(
                credentialRepository = credentialRepository,
                userHandleForResponse = Some(owner.userHandle),
                userHandleForUser = owner.userHandle,
                usernameForRequest = None,
              )
              val step: FinishAssertionSteps[RegisteredCredential]#Step6 =
                steps.begin.next

              step.validations shouldBe a[Success[_]]
              step.tryNext shouldBe a[Success[_]]
            }

            it("Succeeds if credential ID is owned by the user handle in the request.") {
              val steps = finishAssertion(
                credentialRepository = credentialRepository,
                userHandleForRequest = Some(owner.userHandle),
                userHandleForResponse = None,
                userHandleForUser = owner.userHandle,
                usernameForRequest = None,
              )
              val step: FinishAssertionSteps[RegisteredCredential]#Step6 =
                steps.begin.next

              step.validations shouldBe a[Success[_]]
              step.tryNext shouldBe a[Success[_]]
            }
          }
        }

        describe("7. Using credential.id (or credential.rawId, if base64url encoding is inappropriate for your use case), look up the corresponding credential public key and let credentialPublicKey be that credential public key.") {
          it("Fails if the credential ID is unknown.") {
            val steps = finishAssertion(
              credentialRepository = Some(
                Helpers.CredentialRepository.withUser(
                  Defaults.user,
                  RegisteredCredential
                    .builder()
                    .credentialId(
                      Defaults.credentialId.concat(ByteArray.fromHex("00"))
                    )
                    .userHandle(Defaults.userHandle)
                    .publicKeyCose(getPublicKeyBytes(Defaults.credentialKey))
                    .signatureCount(0)
                    .build(),
                )
              )
            )
            val step: steps.Step7 = new steps.Step7(
              Some(Defaults.username).toJava,
              Defaults.userHandle,
              None.toJava,
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
            val step: FinishAssertionSteps[RegisteredCredential]#Step7 =
              steps.begin.next.next

            step.validations shouldBe a[Success[_]]
            step.tryNext shouldBe a[Success[_]]
          }
        }

        describe("8. Let cData, authData and sig denote the value of response’s clientDataJSON, authenticatorData, and signature respectively.") {
          it("Succeeds if all three are present.") {
            val steps = finishAssertion()
            val step: FinishAssertionSteps[RegisteredCredential]#Step8 =
              steps.begin.next.next.next

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

        describe("9. Let JSONtext be the result of running UTF-8 decode on the value of cData.") {
          it("Fails if clientDataJSON is not valid UTF-8.") {
            an[IOException] should be thrownBy new CollectedClientData(
              new ByteArray(Array(-128))
            )
          }
        }

        describe("10. Let C, the client data claimed as used for the signature, be the result of running an implementation-specific JSON parser on JSONtext.") {
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
            val step: FinishAssertionSteps[RegisteredCredential]#Step10 =
              steps.begin.next.next.next.next

            step.validations shouldBe a[Success[_]]
            step.clientData should not be null
            step.tryNext shouldBe a[Success[_]]
          }
        }

        describe(
          "11. Verify that the value of C.type is the string webauthn.get."
        ) {
          it("The default test case succeeds.") {
            val steps = finishAssertion()
            val step: FinishAssertionSteps[RegisteredCredential]#Step11 =
              steps.begin.next.next.next.next.next

            step.validations shouldBe a[Success[_]]
          }

          def assertFails(
              typeString: String,
              isSecurePaymentConfirmation: Option[Boolean] = None,
          ): Unit = {
            val steps = finishAssertion(
              clientDataJson = JacksonCodecs.json.writeValueAsString(
                JacksonCodecs.json
                  .readTree(Defaults.clientDataJson)
                  .asInstanceOf[ObjectNode]
                  .set("type", jsonFactory.textNode(typeString))
              ),
              isSecurePaymentConfirmation = isSecurePaymentConfirmation,
            )
            val step: FinishAssertionSteps[RegisteredCredential]#Step11 =
              steps.begin.next.next.next.next.next

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

          it("""The string "webauthn.create" fails.""") {
            assertFails("webauthn.create")
          }

          it("""The string "payment.get" fails.""") {
            assertFails("payment.get")
          }

          describe("If the isSecurePaymentConfirmation option is set,") {
            it("the default test case fails.") {
              val steps =
                finishAssertion(isSecurePaymentConfirmation = Some(true))
              val step: FinishAssertionSteps[RegisteredCredential]#Step11 =
                steps.begin.next.next.next.next.next

              step.validations shouldBe a[Failure[_]]
              step.validations.failed.get shouldBe an[IllegalArgumentException]
            }

            it("""the default test case succeeds if type is overwritten with the value "payment.get".""") {
              val json = JacksonCodecs.json()
              val steps = finishAssertion(
                isSecurePaymentConfirmation = Some(true),
                clientDataJson = json.writeValueAsString(
                  json
                    .readTree(Defaults.clientDataJson)
                    .asInstanceOf[ObjectNode]
                    .set[ObjectNode]("type", new TextNode("payment.get"))
                ),
              )
              val step: FinishAssertionSteps[RegisteredCredential]#Step11 =
                steps.begin.next.next.next.next.next

              step.validations shouldBe a[Success[_]]
            }

            it("""any value other than "payment.get" fails.""") {
              forAll { (typeString: String) =>
                whenever(typeString != "payment.get") {
                  assertFails(
                    typeString,
                    isSecurePaymentConfirmation = Some(true),
                  )
                }
              }
              forAll(Gen.alphaNumStr) { (typeString: String) =>
                whenever(typeString != "payment.get") {
                  assertFails(
                    typeString,
                    isSecurePaymentConfirmation = Some(true),
                  )
                }
              }
            }

            it("""the string "webauthn.create" fails.""") {
              assertFails(
                "webauthn.create",
                isSecurePaymentConfirmation = Some(true),
              )
            }

            it("""the string "webauthn.get" fails.""") {
              assertFails(
                "webauthn.get",
                isSecurePaymentConfirmation = Some(true),
              )
            }
          }
        }

        it("12. Verify that the value of C.challenge equals the base64url encoding of options.challenge.") {
          val steps =
            finishAssertion(challenge = new ByteArray(Array.fill(16)(0)))
          val step: FinishAssertionSteps[RegisteredCredential]#Step12 =
            steps.begin.next.next.next.next.next.next

          step.validations shouldBe a[Failure[_]]
          step.validations.failed.get shouldBe an[IllegalArgumentException]
          step.tryNext shouldBe a[Failure[_]]
        }

        describe("13. Verify that the value of C.origin matches the Relying Party's origin.") {
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
            val step: FinishAssertionSteps[RegisteredCredential]#Step13 =
              steps.begin.next.next.next.next.next.next.next

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
            val step: FinishAssertionSteps[RegisteredCredential]#Step13 =
              steps.begin.next.next.next.next.next.next.next

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

        describe("14. Verify that the value of C.tokenBinding.status matches the state of Token Binding for the TLS connection over which the attestation was obtained.") {
          it("Verification succeeds if neither side uses token binding ID.") {
            val steps = finishAssertion()
            val step: FinishAssertionSteps[RegisteredCredential]#Step14 =
              steps.begin.next.next.next.next.next.next.next.next

            step.validations shouldBe a[Success[_]]
            step.tryNext shouldBe a[Success[_]]
          }

          it("Verification succeeds if client data specifies token binding is unsupported, and RP does not use it.") {
            val clientDataJson =
              """{"challenge":"AAEBAgMFCA0VIjdZEGl5Yls","origin":"https://localhost","hashAlgorithm":"SHA-256","type":"webauthn.get"}"""
            val steps = finishAssertion(clientDataJson = clientDataJson)
            val step: FinishAssertionSteps[RegisteredCredential]#Step14 =
              steps.begin.next.next.next.next.next.next.next.next

            step.validations shouldBe a[Success[_]]
            step.tryNext shouldBe a[Success[_]]
          }

          it("Verification succeeds if client data specifies token binding is supported, and RP does not use it.") {
            val clientDataJson =
              """{"challenge":"AAEBAgMFCA0VIjdZEGl5Yls","origin":"https://localhost","hashAlgorithm":"SHA-256","tokenBinding":{"status":"supported"},"type":"webauthn.get"}"""
            val steps = finishAssertion(clientDataJson = clientDataJson)
            val step: FinishAssertionSteps[RegisteredCredential]#Step14 =
              steps.begin.next.next.next.next.next.next.next.next

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
            val step: FinishAssertionSteps[RegisteredCredential]#Step14 =
              steps.begin.next.next.next.next.next.next.next.next

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
            val step: FinishAssertionSteps[RegisteredCredential]#Step14 =
              steps.begin.next.next.next.next.next.next.next.next

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
            val step: FinishAssertionSteps[RegisteredCredential]#Step14 =
              steps.begin.next.next.next.next.next.next.next.next

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
              val step: FinishAssertionSteps[RegisteredCredential]#Step14 =
                steps.begin.next.next.next.next.next.next.next.next

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
              val step: FinishAssertionSteps[RegisteredCredential]#Step14 =
                steps.begin.next.next.next.next.next.next.next.next

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
              val step: FinishAssertionSteps[RegisteredCredential]#Step14 =
                steps.begin.next.next.next.next.next.next.next.next

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
              val step: FinishAssertionSteps[RegisteredCredential]#Step14 =
                steps.begin.next.next.next.next.next.next.next.next

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
              val step: FinishAssertionSteps[RegisteredCredential]#Step14 =
                steps.begin.next.next.next.next.next.next.next.next

              step.validations shouldBe a[Failure[_]]
              step.validations.failed.get shouldBe an[IllegalArgumentException]
              step.tryNext shouldBe a[Failure[_]]
            }
          }
        }

        describe("15. Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Relying Party.") {
          it("Fails if RP ID is different.") {
            val steps = finishAssertion(
              rpId = Defaults.rpId.toBuilder.id("root.evil").build(),
              origins = Some(Set("https://localhost")),
            )
            val step: FinishAssertionSteps[RegisteredCredential]#Step15 =
              steps.begin.next.next.next.next.next.next.next.next.next

            step.validations shouldBe a[Failure[_]]
            step.validations.failed.get shouldBe an[IllegalArgumentException]
            step.tryNext shouldBe a[Failure[_]]
          }

          it("Succeeds if RP ID is the same.") {
            val steps = finishAssertion()
            val step: FinishAssertionSteps[RegisteredCredential]#Step15 =
              steps.begin.next.next.next.next.next.next.next.next.next

            step.validations shouldBe a[Success[_]]
            step.tryNext shouldBe a[Success[_]]
          }

          describe("When using the appid extension, it") {
            val appid = new AppId("https://test.example.org/foo")
            val extensions = AssertionExtensionInputs
              .builder()
              .appid(Some(appid).toJava)
              .build()

            it("fails if RP ID is different.") {
              val steps = finishAssertion(
                requestedExtensions = extensions,
                authenticatorData = new ByteArray(
                  Array.fill[Byte](32)(0) ++ Defaults.authenticatorData.getBytes
                    .drop(32)
                ),
              )
              val step: FinishAssertionSteps[RegisteredCredential]#Step15 =
                steps.begin.next.next.next.next.next.next.next.next.next

              step.validations shouldBe a[Failure[_]]
              step.validations.failed.get shouldBe an[IllegalArgumentException]
              step.tryNext shouldBe a[Failure[_]]
            }

            it("succeeds if RP ID is the SHA-256 hash of the standard RP ID.") {
              val steps = finishAssertion(requestedExtensions = extensions)
              val step: FinishAssertionSteps[RegisteredCredential]#Step15 =
                steps.begin.next.next.next.next.next.next.next.next.next

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
              val step: FinishAssertionSteps[RegisteredCredential]#Step15 =
                steps.begin.next.next.next.next.next.next.next.next.next

              step.validations shouldBe a[Success[_]]
              step.tryNext shouldBe a[Success[_]]
            }
          }
        }

        {
          def checks[
              Next <: FinishAssertionSteps.Step[RegisteredCredential, _],
              Step <: FinishAssertionSteps.Step[RegisteredCredential, Next],
          ](
              stepsToStep: FinishAssertionSteps[RegisteredCredential] => Step
          ) = {
            def check[Ret](
                stepsToStep: FinishAssertionSteps[RegisteredCredential] => Step
            )(
                chk: Step => Ret
            )(uvr: UserVerificationRequirement, authData: ByteArray): Ret = {
              val steps = finishAssertion(
                userVerificationRequirement = uvr,
                authenticatorData = authData,
              )
              chk(stepsToStep(steps))
            }
            def checkFailsWith(
                stepsToStep: FinishAssertionSteps[RegisteredCredential] => Step
            ): (UserVerificationRequirement, ByteArray) => Unit =
              check(stepsToStep) { step =>
                step.validations shouldBe a[Failure[_]]
                step.validations.failed.get shouldBe an[
                  IllegalArgumentException
                ]
                step.tryNext shouldBe a[Failure[_]]
              }
            def checkSucceedsWith(
                stepsToStep: FinishAssertionSteps[RegisteredCredential] => Step
            ): (UserVerificationRequirement, ByteArray) => Unit =
              check(stepsToStep) { step =>
                step.validations shouldBe a[Success[_]]
                step.tryNext shouldBe a[Success[_]]
              }

            (checkFailsWith(stepsToStep), checkSucceedsWith(stepsToStep))
          }

          describe("16. Verify that the User Present bit of the flags in authData is set.") {
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
              checks[FinishAssertionSteps[
                RegisteredCredential
              ]#Step17, FinishAssertionSteps[RegisteredCredential]#Step16](
                _.begin.next.next.next.next.next.next.next.next.next.next
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

          describe("17. If user verification is required for this assertion, verify that the User Verified bit of the flags in authData is set.") {
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
              checks[
                FinishAssertionSteps[RegisteredCredential]#PendingStep16,
                FinishAssertionSteps[RegisteredCredential]#Step17,
              ](
                _.begin.next.next.next.next.next.next.next.next.next.next.next
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

        describe("(NOT YET MATURE) 16. If the credential backup state is used as part of Relying Party business logic or policy, let currentBe and currentBs be the values of the BE and BS bits, respectively, of the flags in authData. Compare currentBe and currentBs with credentialRecord.BE and credentialRecord.BS and apply Relying Party policy, if any.") {
          it(
            "Fails if BE=0 in the stored credential and BE=1 in the assertion."
          ) {
            forAll(
              authenticatorDataBytes(
                Gen.option(Extensions.authenticatorAssertionExtensionOutputs()),
                rpIdHashGen = Gen.const(sha256(Defaults.rpId.getId)),
                backupFlagsGen = arbitrary[Boolean].map(bs => (true, bs)),
              )
            ) { authData =>
              val step
                  : FinishAssertionSteps[RegisteredCredential]#PendingStep16 =
                finishAssertion(
                  authenticatorData = authData,
                  credentialRepository = Some(
                    Helpers.CredentialRepository.withUser(
                      Defaults.user,
                      RegisteredCredential
                        .builder()
                        .credentialId(Defaults.credentialId)
                        .userHandle(Defaults.userHandle)
                        .publicKeyCose(
                          getPublicKeyBytes(Defaults.credentialKey)
                        )
                        .backupEligible(false)
                        .backupState(false)
                        .build(),
                    )
                  ),
                ).begin.next.next.next.next.next.next.next.next.next.next.next.next

              step.validations shouldBe a[Failure[_]]
              step.validations.failed.get shouldBe an[IllegalArgumentException]
              step.tryNext shouldBe a[Failure[_]]
            }
          }

          it(
            "Fails if BE=1 in the stored credential and BE=0 in the assertion."
          ) {
            forAll(
              authenticatorDataBytes(
                Gen.option(Extensions.authenticatorAssertionExtensionOutputs()),
                rpIdHashGen = Gen.const(sha256(Defaults.rpId.getId)),
                backupFlagsGen = Gen.const((false, false)),
              ),
              arbitrary[Boolean],
            ) {
              case (authData, storedBs) =>
                val step
                    : FinishAssertionSteps[RegisteredCredential]#PendingStep16 =
                  finishAssertion(
                    authenticatorData = authData,
                    credentialRepository = Some(
                      Helpers.CredentialRepository.withUser(
                        Defaults.user,
                        RegisteredCredential
                          .builder()
                          .credentialId(Defaults.credentialId)
                          .userHandle(Defaults.userHandle)
                          .publicKeyCose(
                            getPublicKeyBytes(Defaults.credentialKey)
                          )
                          .backupEligible(true)
                          .backupState(storedBs)
                          .build(),
                      )
                    ),
                  ).begin.next.next.next.next.next.next.next.next.next.next.next.next

                step.validations shouldBe a[Failure[_]]
                step.validations.failed.get shouldBe an[
                  IllegalArgumentException
                ]
                step.tryNext shouldBe a[Failure[_]]
            }
          }
        }

        describe("18. Verify that the values of the client extension outputs in clientExtensionResults and the authenticator extension outputs in the extensions in authData are as expected, considering the client extension input values that were given in options.extensions and any specific policy of the Relying Party regarding unsolicited extensions, i.e., those that were not specified as part of options.extensions. In the general case, the meaning of \"are as expected\" is specific to the Relying Party and which extensions are in use.") {
          it("Succeeds if clientExtensionResults is not a subset of the extensions requested by the Relying Party.") {
            forAll(Extensions.unrequestedClientAssertionExtensions) {
              case (extensionInputs, clientExtensionOutputs, _) =>
                val steps = finishAssertion(
                  requestedExtensions = extensionInputs,
                  clientExtensionResults = clientExtensionOutputs,
                )
                val step: FinishAssertionSteps[RegisteredCredential]#Step18 =
                  steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next

                step.validations shouldBe a[Success[_]]
                step.tryNext shouldBe a[Success[_]]
            }
          }

          it("Succeeds if clientExtensionResults is a subset of the extensions requested by the Relying Party.") {
            forAll(Extensions.subsetAssertionExtensions) {
              case (extensionInputs, clientExtensionOutputs, _) =>
                val steps = finishAssertion(
                  requestedExtensions = extensionInputs,
                  clientExtensionResults = clientExtensionOutputs,
                )
                val step: FinishAssertionSteps[RegisteredCredential]#Step18 =
                  steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next

                step.validations shouldBe a[Success[_]]
                step.tryNext shouldBe a[Success[_]]
            }
          }

          it("Succeeds if authenticator extensions is not a subset of the extensions requested by the Relying Party.") {
            forAll(Extensions.unrequestedAuthenticatorAssertionExtensions) {
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
                val step: FinishAssertionSteps[RegisteredCredential]#Step18 =
                  steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next

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
                val step: FinishAssertionSteps[RegisteredCredential]#Step18 =
                  steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next

                step.validations shouldBe a[Success[_]]
                step.tryNext shouldBe a[Success[_]]
            }
          }
        }

        it("19. Let hash be the result of computing a hash over the cData using SHA-256.") {
          val steps = finishAssertion()
          val step: FinishAssertionSteps[RegisteredCredential]#Step19 =
            steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next

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

        describe("20. Using credentialPublicKey, verify that sig is a valid signature over the binary concatenation of authData and hash.") {
          it("The default test case succeeds.") {
            val steps = finishAssertion()
            val step: FinishAssertionSteps[RegisteredCredential]#Step20 =
              steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next

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
            val step: FinishAssertionSteps[RegisteredCredential]#Step20 =
              steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next

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
            val step: FinishAssertionSteps[RegisteredCredential]#Step20 =
              steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next

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
            val step: FinishAssertionSteps[RegisteredCredential]#Step20 =
              steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next

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
            val step: FinishAssertionSteps[RegisteredCredential]#Step20 =
              steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next

            step.validations shouldBe a[Failure[_]]
            step.validations.failed.get shouldBe an[IllegalArgumentException]
            step.tryNext shouldBe a[Failure[_]]
          }
        }

        describe("21. Let storedSignCount be the stored signature counter value associated with credential.id. If authData.signCount is nonzero or storedSignCount is nonzero, then run the following sub-step:") {
          describe("If authData.signCount is") {
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
                val step: FinishAssertionSteps[RegisteredCredential]#Step21 =
                  steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next

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
                val step: FinishAssertionSteps[RegisteredCredential]#Step21 =
                  steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next

                step.validations shouldBe a[Failure[_]]
                step.tryNext shouldBe a[Failure[_]]
                step.tryNext.failed.get shouldBe an[
                  InvalidSignatureCountException
                ]
              }
            }

            describe("greater than storedSignCount:") {
              val cr = credentialRepository(1336)

              describe(
                "Update storedSignCount to be the value of authData.signCount."
              ) {
                it("An increasing signature counter always succeeds.") {
                  val steps = finishAssertion(
                    credentialRepository = Some(cr),
                    validateSignatureCounter = true,
                  )
                  val step: FinishAssertionSteps[RegisteredCredential]#Step21 =
                    steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next

                  step.validations shouldBe a[Success[_]]
                  step.tryNext shouldBe a[Success[_]]
                  step.next.result.get.isSignatureCounterValid should be(true)
                  step.next.result.get.getSignatureCount should be(1337)
                }
              }
            }

            describe("less than or equal to storedSignCount:") {
              val cr = credentialRepository(1337)

              describe("This is a signal that the authenticator may be cloned, i.e. at least two copies of the credential private key may exist and are being used in parallel. Relying Parties should incorporate this information into their risk scoring. Whether the Relying Party updates storedSignCount in this case, or not, or fails the authentication ceremony or not, is Relying Party-specific.") {
                it("If signature counter validation is disabled, a nonincreasing signature counter succeeds.") {
                  val steps = finishAssertion(
                    credentialRepository = Some(cr),
                    validateSignatureCounter = false,
                  )
                  val step: FinishAssertionSteps[RegisteredCredential]#Step21 =
                    steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next

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
                  val step: FinishAssertionSteps[RegisteredCredential]#Step21 =
                    steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next
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

        it("22. If all the above steps are successful, continue with the authentication ceremony as appropriate. Otherwise, fail the authentication ceremony.") {
          val steps = finishAssertion()
          val step: FinishAssertionSteps[RegisteredCredential]#Finished =
            steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next

          step.validations shouldBe a[Success[_]]
          Try(steps.run) shouldBe a[Success[_]]

          step.result.get.isSuccess should be(true)
          step.result.get.getCredential.getCredentialId should equal(
            Defaults.credentialId
          )
          step.result.get.getCredential.getUserHandle should equal(
            Defaults.userHandle
          )
          step.result.get.getCredential.getCredentialId should equal(
            step.result.get.getCredentialId
          )
          step.result.get.getCredential.getUserHandle should equal(
            step.result.get.getUserHandle
          )
          step.result.get.getCredential.getPublicKeyCose should not be null
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
        result.getCredential.getUserHandle should equal(testData.userId.getId)
        result.getCredential.getCredentialId should equal(credId)
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
        result.getCredential.getUserHandle should equal(
          registrationRequest.getUser.getId
        )
        result.getCredential.getCredentialId should equal(credId)
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
        result.getCredential.getUserHandle should equal(
          registrationTestData.userId.getId
        )
        result.getCredential.getCredentialId should equal(
          registrationTestData.response.getId
        )
        result.getCredential.getCredentialId should equal(
          testData.response.getId
        )
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
          result.getCredential.getUserHandle should equal(
            registrationTestData.userId.getId
          )
          result.getCredential.getCredentialId should equal(
            registrationTestData.response.getId
          )
          result.getCredential.getCredentialId should equal(
            testData.response.getId
          )
        }

        it("with basic attestation.") {
          test(RegistrationTestData.Packed.BasicAttestationRs1)
        }
        it("with self attestation.") {
          test(RegistrationTestData.Packed.SelfAttestationRs1)
        }
      }

      it("a U2F-formatted public key.") {
        val testData = RealExamples.YubiKeyNeo.asRegistrationTestData
        val x = ByteArray.fromHex(
          "39C94FBBDDC694A925E6F8657C66916CFE84CD0222EDFCF281B21F5CDC347923"
        )
        val y = ByteArray.fromHex(
          "D6B0D2021CFE1724A6FE81E3568C4FFAE339298216A30AFC18C0B975F2E2A891"
        )
        val u2fPubkey = ByteArray.fromHex("04").concat(x).concat(y)

        val cred1 = RegisteredCredential
          .builder()
          .credentialId(testData.assertion.get.response.getId)
          .userHandle(testData.userId.getId)
          .publicKeyEs256Raw(u2fPubkey)
          .signatureCount(0)
          .build()

        val cred2 = RegisteredCredential
          .builder()
          .credentialId(testData.assertion.get.response.getId)
          .userHandle(testData.userId.getId)
          .publicKeyCose(u2fPubkey)
          .signatureCount(0)
          .publicKeyEs256Raw(u2fPubkey)
          .build()

        for { cred <- List(cred1, cred2) } {
          val rp = RelyingParty
            .builder()
            .identity(testData.rpId)
            .credentialRepository(
              Helpers.CredentialRepository.withUser(testData.userId, cred)
            )
            .build()

          val result = rp.finishAssertion(
            FinishAssertionOptions
              .builder()
              .request(testData.assertion.get.request)
              .response(testData.assertion.get.response)
              .build()
          )

          result.isSuccess should be(true)
          result.getCredential.getUserHandle should equal(testData.userId.getId)
          result.getCredential.getCredentialId should equal(
            testData.response.getId
          )
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
                        LargeBlobAuthenticationOutput.write(true)
                      )
                      .build()
                  )
                  .build()
              )
              .build()
          )

          result.getClientExtensionOutputs.get.getLargeBlob.get.getWritten.toScala should be(
            Some(true)
          )
          result.getClientExtensionOutputs.get.getLargeBlob.get.getBlob.toScala should be(
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
                        LargeBlobAuthenticationOutput
                          .read(ByteArray.fromHex("00010203"))
                      )
                      .build()
                  )
                  .build()
              )
              .build()
          )

          result.getClientExtensionOutputs.get.getLargeBlob.get.getBlob.toScala should be(
            Some(ByteArray.fromHex("00010203"))
          )
          result.getClientExtensionOutputs.get.getLargeBlob.get.getWritten.toScala should be(
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

          result.getAuthenticatorExtensionOutputs.get.getUvm.toScala should equal(
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

      describe("returns AssertionResponse which") {
        {
          val user = UserIdentity.builder
            .name("foo")
            .displayName("Foo User")
            .id(new ByteArray(Array(0, 1, 2, 3)))
            .build()
          val (credential, credentialKeypair, _) =
            TestAuthenticator.createUnattestedCredential()
          val rp = RelyingParty
            .builder()
            .identity(
              RelyingPartyIdentity
                .builder()
                .id("localhost")
                .name("Example RP")
                .build()
            )
            .credentialRepository(
              Helpers.CredentialRepository.withUser(
                user,
                RegisteredCredential
                  .builder()
                  .credentialId(credential.getId)
                  .userHandle(user.getId)
                  .publicKeyCose(
                    credential.getResponse.getParsedAuthenticatorData.getAttestedCredentialData.get.getCredentialPublicKey
                  )
                  .build(),
              )
            )
            .build()

          val request = AssertionRequest
            .builder()
            .publicKeyCredentialRequestOptions(
              PublicKeyCredentialRequestOptions
                .builder()
                .challenge(ByteArray.fromBase64Url("Y2hhbGxlbmdl"))
                .rpId("localhost")
                .build()
            )
            .username(user.getName)
            .build()

          it("exposes isUserVerified() with the UV flag value in authenticator data.") {
            val pkcWithoutUv =
              TestAuthenticator.createAssertion(
                flags = Some(new AuthenticatorDataFlags(0x00.toByte)),
                challenge =
                  request.getPublicKeyCredentialRequestOptions.getChallenge,
                credentialKey = credentialKeypair,
                credentialId = credential.getId,
              )
            val pkcWithUv =
              TestAuthenticator.createAssertion(
                flags = Some(new AuthenticatorDataFlags(0x04.toByte)),
                challenge =
                  request.getPublicKeyCredentialRequestOptions.getChallenge,
                credentialKey = credentialKeypair,
                credentialId = credential.getId,
              )

            val resultWithoutUv = rp.finishAssertion(
              FinishAssertionOptions
                .builder()
                .request(request)
                .response(pkcWithoutUv)
                .build()
            )
            val resultWithUv = rp.finishAssertion(
              FinishAssertionOptions
                .builder()
                .request(request)
                .response(pkcWithUv)
                .build()
            )

            resultWithoutUv.isUserVerified should be(false)
            resultWithUv.isUserVerified should be(true)
          }

          it("exposes isBackupEligible() with the BE flag value in authenticator data.") {
            val pkcWithoutBackup =
              TestAuthenticator.createAssertion(
                flags = Some(new AuthenticatorDataFlags(0x00.toByte)),
                challenge =
                  request.getPublicKeyCredentialRequestOptions.getChallenge,
                credentialKey = credentialKeypair,
                credentialId = credential.getId,
              )
            val pkcWithBackup =
              TestAuthenticator.createAssertion(
                flags = Some(new AuthenticatorDataFlags(0x08.toByte)),
                challenge =
                  request.getPublicKeyCredentialRequestOptions.getChallenge,
                credentialKey = credentialKeypair,
                credentialId = credential.getId,
              )

            val resultWithoutBackup = rp.finishAssertion(
              FinishAssertionOptions
                .builder()
                .request(request)
                .response(pkcWithoutBackup)
                .build()
            )
            val resultWithBackup = rp.finishAssertion(
              FinishAssertionOptions
                .builder()
                .request(request)
                .response(pkcWithBackup)
                .build()
            )

            resultWithoutBackup.isBackupEligible should be(false)
            resultWithBackup.isBackupEligible should be(true)
          }

          it(
            "exposes isBackedUp() with the BS flag value in authenticator data."
          ) {
            val pkcWithoutBackup =
              TestAuthenticator.createAssertion(
                flags = Some(new AuthenticatorDataFlags(0x00.toByte)),
                challenge =
                  request.getPublicKeyCredentialRequestOptions.getChallenge,
                credentialKey = credentialKeypair,
                credentialId = credential.getId,
              )
            val pkcWithBeOnly =
              TestAuthenticator.createAssertion(
                flags = Some(new AuthenticatorDataFlags(0x08.toByte)),
                challenge =
                  request.getPublicKeyCredentialRequestOptions.getChallenge,
                credentialKey = credentialKeypair,
                credentialId = credential.getId,
              )
            val pkcWithBackup =
              TestAuthenticator.createAssertion(
                flags = Some(new AuthenticatorDataFlags(0x18.toByte)),
                challenge =
                  request.getPublicKeyCredentialRequestOptions.getChallenge,
                credentialKey = credentialKeypair,
                credentialId = credential.getId,
              )

            val resultWithBackup = rp.finishAssertion(
              FinishAssertionOptions
                .builder()
                .request(request)
                .response(pkcWithBackup)
                .build()
            )
            val resultWithBeOnly = rp.finishAssertion(
              FinishAssertionOptions
                .builder()
                .request(request)
                .response(pkcWithBeOnly)
                .build()
            )
            val resultWithoutBackup = rp.finishAssertion(
              FinishAssertionOptions
                .builder()
                .request(request)
                .response(pkcWithoutBackup)
                .build()
            )

            resultWithoutBackup.isBackedUp should be(false)
            resultWithBeOnly.isBackedUp should be(false)
            resultWithBackup.isBackedUp should be(true)
          }

          it(
            "exposes getAuthenticatorAttachment() with the authenticatorAttachment value from the PublicKeyCredential."
          ) {
            val pkcTemplate =
              TestAuthenticator.createAssertion(
                challenge =
                  request.getPublicKeyCredentialRequestOptions.getChallenge,
                credentialKey = credentialKeypair,
                credentialId = credential.getId,
              )

            forAll { authenticatorAttachment: Option[AuthenticatorAttachment] =>
              val pkc = pkcTemplate.toBuilder
                .authenticatorAttachment(authenticatorAttachment.orNull)
                .build()

              val result = rp.finishAssertion(
                FinishAssertionOptions
                  .builder()
                  .request(request)
                  .response(pkc)
                  .build()
              )

              result.getAuthenticatorAttachment should equal(
                pkc.getAuthenticatorAttachment
              )
            }
          }

          describe("exposes the credProps.authenticatorDisplayName extension output as getAuthenticatorDisplayName()") {
            val pkcTemplate =
              TestAuthenticator.createAssertion(
                challenge =
                  request.getPublicKeyCredentialRequestOptions.getChallenge,
                credentialKey = credentialKeypair,
                credentialId = credential.getId,
              )

            it("""when set to "hej".""") {
              val pkc = pkcTemplate.toBuilder
                .clientExtensionResults(
                  pkcTemplate.getClientExtensionResults.toBuilder
                    .credProps(
                      CredentialPropertiesOutput
                        .builder()
                        .authenticatorDisplayName("hej")
                        .build()
                    )
                    .build()
                )
                .build()
              val result = rp.finishAssertion(
                FinishAssertionOptions
                  .builder()
                  .request(request)
                  .response(pkc)
                  .build()
              )

              result.getAuthenticatorDisplayName.toScala should equal(
                Some("hej")
              )
            }

            it("when not available.") {
              val pkc = pkcTemplate
              val result = rp.finishAssertion(
                FinishAssertionOptions
                  .builder()
                  .request(request)
                  .response(pkc)
                  .build()
              )

              result.getAuthenticatorDisplayName.toScala should equal(None)
            }
          }
        }
      }
    }
  }

}
