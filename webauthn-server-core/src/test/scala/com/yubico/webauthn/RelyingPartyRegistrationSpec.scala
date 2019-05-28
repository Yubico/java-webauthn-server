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

import java.util
import java.io.IOException
import java.nio.charset.Charset
import java.security.MessageDigest
import java.security.KeyPair
import java.security.PrivateKey
import java.security.SignatureException
import java.security.cert.X509Certificate
import java.util.Optional

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.node.JsonNodeFactory
import com.fasterxml.jackson.databind.node.ObjectNode
import com.upokecenter.cbor.CBORObject
import com.yubico.internal.util.WebAuthnCodecs
import com.yubico.internal.util.scala.JavaConverters._
import com.yubico.webauthn.attestation.MetadataService
import com.yubico.webauthn.attestation.Attestation
import com.yubico.webauthn.data.RelyingPartyIdentity
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria
import com.yubico.webauthn.data.AttestationObject
import com.yubico.webauthn.data.AuthenticatorData
import com.yubico.webauthn.data.UserVerificationRequirement
import com.yubico.webauthn.data.AttestationType
import com.yubico.webauthn.data.CollectedClientData
import com.yubico.webauthn.data.ByteArray
import com.yubico.webauthn.data.RegistrationExtensionInputs
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor
import com.yubico.webauthn.data.UserIdentity
import com.yubico.webauthn.data.AttestationConveyancePreference
import com.yubico.webauthn.data.Generators._
import com.yubico.webauthn.test.Util.toStepWithUtilities
import javax.security.auth.x500.X500Principal
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.x500.X500Name
import org.junit.runner.RunWith
import org.mockito.Mockito
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
class RelyingPartyRegistrationSpec extends FunSpec with Matchers with GeneratorDrivenPropertyChecks {

  private def jsonFactory: JsonNodeFactory = JsonNodeFactory.instance
  private def toJsonObject(obj: Map[String, JsonNode]): JsonNode = jsonFactory.objectNode().setAll(obj.asJava)
  private def toJson(obj: Map[String, String]): JsonNode = toJsonObject(obj.mapValues(jsonFactory.textNode))

  private val crypto = new BouncyCastleCrypto
  private def sha256(bytes: ByteArray): ByteArray = crypto.hash(bytes)

  def flipByte(index: Int, bytes: ByteArray): ByteArray = editByte(bytes, index, b => (0xff ^ b).toByte)
  def editByte(bytes: ByteArray, index: Int, updater: Byte => Byte): ByteArray = new ByteArray(bytes.getBytes.updated(index, updater(bytes.getBytes()(index))))

  private val emptyCredentialRepository = new CredentialRepository {
    override def getCredentialIdsForUsername(username: String): java.util.Set[PublicKeyCredentialDescriptor] = Set.empty.asJava
    override def getUserHandleForUsername(username: String): Optional[ByteArray] = None.asJava
    override def getUsernameForUserHandle(userHandle: ByteArray): Optional[String] = None.asJava
    override def lookup(credentialId: ByteArray, userHandle: ByteArray): Optional[RegisteredCredential] = None.asJava
    override def lookupAll(credentialId: ByteArray): java.util.Set[RegisteredCredential] = Set.empty.asJava
  }

  private val unimplementedCredentialRepository = new CredentialRepository {
    override def getCredentialIdsForUsername(username: String): util.Set[PublicKeyCredentialDescriptor] = ???
    override def getUserHandleForUsername(username: String): Optional[ByteArray] = ???
    override def getUsernameForUserHandle(userHandleBase64: ByteArray): Optional[String] = ???
    override def lookup(credentialId: ByteArray, userHandle: ByteArray): Optional[RegisteredCredential] = ???
    override def lookupAll(credentialId: ByteArray): util.Set[RegisteredCredential] = ???
  }

  private def finishRegistration(
    allowUntrustedAttestation: Boolean = false,
    callerTokenBindingId: Option[ByteArray] = None,
    credentialId: Option[ByteArray] = None,
    credentialRepository: Option[CredentialRepository] = None,
    metadataService: Option[MetadataService] = None,
    rp: RelyingPartyIdentity = RelyingPartyIdentity.builder().id("localhost").name("Test party").build(),
    testData: RegistrationTestData
  ): FinishRegistrationSteps = {
    RelyingParty.builder()
      .identity(rp)
      .credentialRepository(credentialRepository.getOrElse(unimplementedCredentialRepository))
      .preferredPubkeyParams(Nil.asJava)
      .origins(Set("https://" + rp.getId).asJava)
      .allowUntrustedAttestation(allowUntrustedAttestation)
      .metadataService(metadataService.asJava)
      .build()
      ._finishRegistration(testData.request, testData.response, callerTokenBindingId.asJava)
  }

  class TestMetadataService(private val attestation: Option[Attestation] = None) extends MetadataService {
    override def getAttestation(attestationCertificateChain: java.util.List[X509Certificate]): Attestation = attestation match {
      case None => Attestation.builder().trusted(false).build()
      case Some(a) => a
    }
  }

  describe("§7.1. Registering a new credential") {

    describe("When registering a new credential, represented by an AuthenticatorAttestationResponse structure response and an AuthenticationExtensionsClientOutputs structure clientExtensionResults, as part of a registration ceremony, a Relying Party MUST proceed as follows:") {

      describe("1. Let JSONtext be the result of running UTF-8 decode on the value of response.clientDataJSON.") {
        it("Nothing to test.") {}
      }

      describe("2. Let C, the client data claimed as collected during the credential creation, be the result of running an implementation-specific JSON parser on JSONtext.") {

        it("Fails if clientDataJson is not valid JSON.") {
          an [IOException] should be thrownBy new CollectedClientData(new ByteArray("{".getBytes(Charset.forName("UTF-8"))))
          an [IOException] should be thrownBy finishRegistration(
            testData = RegistrationTestData.FidoU2f.BasicAttestation.copy(clientDataJson = "{")
          )
        }

        it("Succeeds if clientDataJson is valid JSON.") {
          val steps = finishRegistration(
            testData = RegistrationTestData.FidoU2f.BasicAttestation.copy(
              clientDataJson =
                """{
                  "challenge": "",
                  "origin": "",
                  "type": ""
                }""",
              overrideRequest = Some(RegistrationTestData.FidoU2f.BasicAttestation.request)
            )
          )
          val step: FinishRegistrationSteps#Step2 = steps.begin.next

          step.validations shouldBe a [Success[_]]
          step.clientData should not be null
          step.tryNext shouldBe a [Success[_]]
        }
      }

      describe("3. Verify that the value of C.type is webauthn.create.") {
        it("The default test case succeeds.") {
          val steps = finishRegistration(testData = RegistrationTestData.FidoU2f.BasicAttestation)
          val step: FinishRegistrationSteps#Step3 = steps.begin.next.next

          step.validations shouldBe a [Success[_]]
        }


        def assertFails(typeString: String): Unit = {
          val steps = finishRegistration(
            testData = RegistrationTestData.FidoU2f.BasicAttestation.editClientData("type", typeString)
          )
          val step: FinishRegistrationSteps#Step3 = steps.begin.next.next

          step.validations shouldBe a [Failure[_]]
          step.validations.failed.get shouldBe an [IllegalArgumentException]
        }

        it("""Any value other than "webauthn.create" fails.""") {
          forAll { (typeString: String) =>
            whenever (typeString != "webauthn.create") {
              assertFails(typeString)
            }
          }
          forAll(Gen.alphaNumStr) { (typeString: String) =>
            whenever (typeString != "webauthn.create") {
              assertFails(typeString)
            }
          }
        }
      }

      it("4. Verify that the value of C.challenge matches the challenge that was sent to the authenticator in the create() call.") {
        val steps = finishRegistration(
          testData = RegistrationTestData.FidoU2f.BasicAttestation.copy(
            overrideRequest = Some(RegistrationTestData.FidoU2f.BasicAttestation.request.toBuilder.challenge(new ByteArray(Array.fill(16)(0))).build())
          )
        )
        val step: FinishRegistrationSteps#Step4 = steps.begin.next.next.next

        step.validations shouldBe a [Failure[_]]
        step.validations.failed.get shouldBe an [IllegalArgumentException]
        step.tryNext shouldBe a [Failure[_]]
      }

      it("5. Verify that the value of C.origin matches the Relying Party's origin.") {
        val steps = finishRegistration(
          testData = RegistrationTestData.FidoU2f.BasicAttestation.editClientData("origin", "https://root.evil")
        )
        val step: FinishRegistrationSteps#Step5 = steps.begin.next.next.next.next

        step.validations shouldBe a [Failure[_]]
        step.validations.failed.get shouldBe an [IllegalArgumentException]
        step.tryNext shouldBe a [Failure[_]]
      }

      describe("6. Verify that the value of C.tokenBinding.status matches the state of Token Binding for the TLS connection over which the assertion was obtained.") {
        it("Verification succeeds if neither side uses token binding ID.") {
          val steps = finishRegistration(testData = RegistrationTestData.FidoU2f.BasicAttestation)
          val step: FinishRegistrationSteps#Step6 = steps.begin.next.next.next.next.next

          step.validations shouldBe a [Success[_]]
          step.tryNext shouldBe a [Success[_]]
        }

        it("Verification succeeds if client data specifies token binding is unsupported, and RP does not use it.") {
          val steps = finishRegistration(testData = RegistrationTestData.FidoU2f.BasicAttestation
            .editClientData(_.without("tokenBinding"))
          )
          val step: FinishRegistrationSteps#Step6 = steps.begin.next.next.next.next.next

          step.validations shouldBe a [Success[_]]
          step.tryNext shouldBe a [Success[_]]
        }

        it("Verification succeeds if client data specifies token binding is supported, and RP does not use it.") {
          val steps = finishRegistration(testData = RegistrationTestData.FidoU2f.BasicAttestation
            .editClientData("tokenBinding", toJson(Map("status" -> "supported")))
          )
          val step: FinishRegistrationSteps#Step6 = steps.begin.next.next.next.next.next

          step.validations shouldBe a [Success[_]]
          step.tryNext shouldBe a [Success[_]]
        }

        it("Verification fails if client data does not specify token binding status and RP specifies token binding ID.") {
          val steps = finishRegistration(
            callerTokenBindingId = Some(ByteArray.fromBase64Url("YELLOWSUBMARINE")),
            testData = RegistrationTestData.FidoU2f.BasicAttestation.editClientData(_.without("tokenBinding"))
          )
          val step: FinishRegistrationSteps#Step6 = steps.begin.next.next.next.next.next

          step.validations shouldBe a [Failure[_]]
          step.validations.failed.get shouldBe an [IllegalArgumentException]
          step.tryNext shouldBe a [Failure[_]]
        }

        it("Verification succeeds if client data does not specify token binding status and RP does not specify token binding ID.") {
          val steps = finishRegistration(
            callerTokenBindingId = None,
            testData = RegistrationTestData.FidoU2f.BasicAttestation.editClientData(_.without("tokenBinding"))
          )
          val step: FinishRegistrationSteps#Step6 = steps.begin.next.next.next.next.next

          step.validations shouldBe a [Success[_]]
          step.tryNext shouldBe a [Success[_]]
        }
        it("Verification fails if client data specifies token binding ID but RP does not.") {
          val steps = finishRegistration(
            callerTokenBindingId = None,
            testData = RegistrationTestData.FidoU2f.BasicAttestation.editClientData("tokenBinding", toJson(Map("status" -> "present", "id" -> "YELLOWSUBMARINE")))
          )
          val step: FinishRegistrationSteps#Step6 = steps.begin.next.next.next.next.next

          step.validations shouldBe a [Failure[_]]
          step.validations.failed.get shouldBe an [IllegalArgumentException]
          step.tryNext shouldBe a [Failure[_]]
        }

        describe("If Token Binding was used on that TLS connection, also verify that C.tokenBinding.id matches the base64url encoding of the Token Binding ID for the connection.") {
          it("Verification succeeds if both sides specify the same token binding ID.") {
            val steps = finishRegistration(
              callerTokenBindingId = Some(ByteArray.fromBase64Url("YELLOWSUBMARINE")),
              testData = RegistrationTestData.FidoU2f.BasicAttestation.editClientData("tokenBinding", toJson(Map("status" -> "present", "id" -> "YELLOWSUBMARINE")))
            )
            val step: FinishRegistrationSteps#Step6 = steps.begin.next.next.next.next.next

            step.validations shouldBe a [Success[_]]
            step.tryNext shouldBe a [Success[_]]
          }

          it("Verification fails if ID is missing from tokenBinding in client data.") {
            val steps = finishRegistration(
              callerTokenBindingId = Some(ByteArray.fromBase64Url("YELLOWSUBMARINE")),
              testData = RegistrationTestData.FidoU2f.BasicAttestation.editClientData("tokenBinding", toJson(Map("status" -> "present")))
            )
            val step: FinishRegistrationSteps#Step6 = steps.begin.next.next.next.next.next

            step.validations shouldBe a [Failure[_]]
            step.validations.failed.get shouldBe an [IllegalArgumentException]
            step.tryNext shouldBe a [Failure[_]]
          }

          it("Verification fails if RP specifies token binding ID but client does not support it.") {
            val steps = finishRegistration(
              callerTokenBindingId = Some(ByteArray.fromBase64Url("YELLOWSUBMARINE")),
              testData = RegistrationTestData.FidoU2f.BasicAttestation.editClientData(_.without("tokenBinding"))
            )
            val step: FinishRegistrationSteps#Step6 = steps.begin.next.next.next.next.next

            step.validations shouldBe a [Failure[_]]
            step.validations.failed.get shouldBe an [IllegalArgumentException]
            step.tryNext shouldBe a [Failure[_]]
          }

          it("Verification fails if RP specifies token binding ID but client does not use it.") {
            val steps = finishRegistration(
              callerTokenBindingId = Some(ByteArray.fromBase64Url("YELLOWSUBMARINE")),
              testData = RegistrationTestData.FidoU2f.BasicAttestation.editClientData("tokenBinding", toJson(Map("status" -> "supported")))
            )
            val step: FinishRegistrationSteps#Step6 = steps.begin.next.next.next.next.next

            step.validations shouldBe a [Failure[_]]
            step.validations.failed.get shouldBe an [IllegalArgumentException]
            step.tryNext shouldBe a [Failure[_]]
          }

          it("Verification fails if client data and RP specify different token binding IDs.") {
            val steps = finishRegistration(
              callerTokenBindingId = Some(ByteArray.fromBase64Url("ORANGESUBMARINE")),
              testData = RegistrationTestData.FidoU2f.BasicAttestation.editClientData("tokenBinding", toJson(Map("status" -> "supported", "id" -> "YELLOWSUBMARINE")))
            )
            val step: FinishRegistrationSteps#Step6 = steps.begin.next.next.next.next.next

            step.validations shouldBe a [Failure[_]]
            step.validations.failed.get shouldBe an [IllegalArgumentException]
            step.tryNext shouldBe a [Failure[_]]
          }
        }

      }

      it("7. Compute the hash of response.clientDataJSON using SHA-256.") {
        val steps = finishRegistration(testData = RegistrationTestData.FidoU2f.BasicAttestation)
        val step: FinishRegistrationSteps#Step7 = steps.begin.next.next.next.next.next.next

        step.validations shouldBe a [Success[_]]
        step.tryNext shouldBe a [Success[_]]
        step.clientDataJsonHash should equal (new ByteArray(MessageDigest.getInstance("SHA-256", crypto.getProvider).digest(RegistrationTestData.FidoU2f.BasicAttestation.clientDataJsonBytes.getBytes)))
      }

      it("8. Perform CBOR decoding on the attestationObject field of the AuthenticatorAttestationResponse structure to obtain the attestation statement format fmt, the authenticator data authData, and the attestation statement attStmt.") {
        val steps = finishRegistration(testData = RegistrationTestData.FidoU2f.BasicAttestation)
        val step: FinishRegistrationSteps#Step8 = steps.begin.next.next.next.next.next.next.next

        step.validations shouldBe a [Success[_]]
        step.tryNext shouldBe a [Success[_]]
        step.attestation.getFormat should equal ("fido-u2f")
        step.attestation.getAuthenticatorData should not be null
        step.attestation.getAttestationStatement should not be null
      }

      describe("9. Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Relying Party.") {
        it("Fails if RP ID is different.") {
          val steps = finishRegistration(
            testData = RegistrationTestData.FidoU2f.BasicAttestation.editAuthenticatorData { authData: ByteArray =>
              new ByteArray(Array.fill[Byte](32)(0) ++ authData.getBytes.drop(32))
            }
          )
          val step: FinishRegistrationSteps#Step9 = steps.begin.next.next.next.next.next.next.next.next

          step.validations shouldBe a [Failure[_]]
          step.validations.failed.get shouldBe an [IllegalArgumentException]
          step.tryNext shouldBe a [Failure[_]]
        }

        it("Succeeds if RP ID is the same.") {
          val steps = finishRegistration(testData = RegistrationTestData.FidoU2f.BasicAttestation)
          val step: FinishRegistrationSteps#Step9 = steps.begin.next.next.next.next.next.next.next.next

          step.validations shouldBe a [Success[_]]
          step.tryNext shouldBe a [Success[_]]
        }
      }

      {
        val testData = RegistrationTestData.Packed.BasicAttestation

        def upOn(authData: ByteArray): ByteArray = new ByteArray(authData.getBytes.updated(32, (authData.getBytes()(32) | 0x01).toByte))
        def upOff(authData: ByteArray): ByteArray = new ByteArray(authData.getBytes.updated(32, (authData.getBytes()(32) & 0xfe).toByte))

        def uvOn(authData: ByteArray): ByteArray = new ByteArray(authData.getBytes.updated(32, (authData.getBytes()(32) | 0x04).toByte))
        def uvOff(authData: ByteArray): ByteArray = new ByteArray(authData.getBytes.updated(32, (authData.getBytes()(32) & 0xfb).toByte))

        def checks[Next <: FinishRegistrationSteps.Step[_], Step <: FinishRegistrationSteps.Step[Next]](stepsToStep: FinishRegistrationSteps => Step) = {
          def check[B]
            (stepsToStep: FinishRegistrationSteps => Step)
            (chk: Step => B)
            (uvr: UserVerificationRequirement, authDataEdit: ByteArray => ByteArray)
          : B = {
            val steps = finishRegistration(
              testData = testData.copy(
                authenticatorSelection = Some(AuthenticatorSelectionCriteria.builder().userVerification(uvr).build())
              ).editAuthenticatorData(authDataEdit)
            )
            chk(stepsToStep(steps))
          }
          def checkFailsWith(stepsToStep: FinishRegistrationSteps => Step): (UserVerificationRequirement, ByteArray => ByteArray) => Unit = check(stepsToStep) { step =>
            step.validations shouldBe a [Failure[_]]
            step.validations.failed.get shouldBe an [IllegalArgumentException]
            step.tryNext shouldBe a [Failure[_]]
          }
          def checkSucceedsWith(stepsToStep: FinishRegistrationSteps => Step): (UserVerificationRequirement, ByteArray => ByteArray) => Unit = check(stepsToStep) { step =>
            step.validations shouldBe a [Success[_]]
            step.tryNext shouldBe a [Success[_]]
          }

          (checkFailsWith(stepsToStep), checkSucceedsWith(stepsToStep))
        }

        describe("10. Verify that the User Present bit of the flags in authData is set.") {
          val (checkFails, checkSucceeds) = checks[FinishRegistrationSteps#Step11, FinishRegistrationSteps#Step10](_.begin.next.next.next.next.next.next.next.next.next)

          it("Fails if UV is discouraged and flag is not set.") {
            checkFails(UserVerificationRequirement.DISCOURAGED, upOff)
          }

          it("Succeeds if UV is discouraged and flag is set.") {
            checkSucceeds(UserVerificationRequirement.DISCOURAGED, upOn)
          }

          it("Fails if UV is preferred and flag is not set.") {
            checkFails(UserVerificationRequirement.PREFERRED, upOff)
          }

          it("Succeeds if UV is preferred and flag is set.") {
            checkSucceeds(UserVerificationRequirement.PREFERRED, upOn)
          }

          it("Fails if UV is required and flag is not set.") {
            checkFails(UserVerificationRequirement.REQUIRED, upOff _ andThen uvOn)
          }

          it("Succeeds if UV is required and flag is set.") {
            checkSucceeds(UserVerificationRequirement.REQUIRED, upOn _ andThen uvOn)
          }
        }

        describe("11. If user verification is required for this registration, verify that the User Verified bit of the flags in authData is set.") {
          val (checkFails, checkSucceeds) = checks[FinishRegistrationSteps#Step12, FinishRegistrationSteps#Step11](_.begin.next.next.next.next.next.next.next.next.next.next)

          it("Succeeds if UV is discouraged and flag is not set.") {
            checkSucceeds(UserVerificationRequirement.DISCOURAGED, uvOff)
          }

          it("Succeeds if UV is discouraged and flag is set.") {
            checkSucceeds(UserVerificationRequirement.DISCOURAGED, uvOn)
          }

          it("Succeeds if UV is preferred and flag is not set.") {
            checkSucceeds(UserVerificationRequirement.PREFERRED, uvOff)
          }

          it("Succeeds if UV is preferred and flag is set.") {
            checkSucceeds(UserVerificationRequirement.PREFERRED, uvOn)
          }

          it("Fails if UV is required and flag is not set.") {
            checkFails(UserVerificationRequirement.REQUIRED, uvOff)
          }

          it("Succeeds if UV is required and flag is set.") {
            checkSucceeds(UserVerificationRequirement.REQUIRED, uvOn)
          }
        }
      }

      describe("12. Verify that the values of the") {

        describe("client extension outputs in clientExtensionResults are as expected, considering the client extension input values that were given as the extensions option in the create() call. In particular, any extension identifier values in the clientExtensionResults MUST be also be present as extension identifier values in the extensions member of options, i.e., no extensions are present that were not requested. In the general case, the meaning of \"are as expected\" is specific to the Relying Party and which extensions are in use.") {
          ignore("Fails if clientExtensionResults is not a subset of the extensions requested by the Relying Party.") {
            forAll(anyRegistrationExtensions) { case (extensionInputs, clientExtensionOutputs) =>
              whenever(clientExtensionOutputs.getExtensionIds.asScala.exists(id => !extensionInputs.getExtensionIds.contains(id))) {
                val steps = finishRegistration(
                  testData = RegistrationTestData.Packed.BasicAttestation.copy(
                    requestedExtensions = extensionInputs,
                    clientExtensionResults = clientExtensionOutputs
                  )
                )
                val step: FinishRegistrationSteps#Step12 = steps.begin.next.next.next.next.next.next.next.next.next.next.next

                step.validations shouldBe a [Failure[_]]
                step.validations.failed.get shouldBe an [IllegalArgumentException]
                step.tryNext shouldBe a [Failure[_]]
              }
            }
          }

          it("Succeeds if clientExtensionResults is a subset of the extensions requested by the Relying Party.") {
            forAll(subsetRegistrationExtensions) { case (extensionInputs, clientExtensionOutputs) =>
              val steps = finishRegistration(
                testData = RegistrationTestData.Packed.BasicAttestation.copy(
                  requestedExtensions = extensionInputs,
                  clientExtensionResults = clientExtensionOutputs
                )
              )
              val step: FinishRegistrationSteps#Step12 = steps.begin.next.next.next.next.next.next.next.next.next.next.next

              step.validations shouldBe a [Success[_]]
              step.tryNext shouldBe a [Success[_]]
            }
          }
        }

        describe("authenticator extension outputs in the extensions in authData are as expected, considering the client extension input values that were given as the extensions option in the create() call. In particular, any extension identifier values in the extensions in authData MUST be also be present as extension identifier values in the extensions member of options, i.e., no extensions are present that were not requested. In the general case, the meaning of \"are as expected\" is specific to the Relying Party and which extensions are in use.") {
          it("Fails if authenticator extensions is not a subset of the extensions requested by the Relying Party.") {
            forAll(anyAuthenticatorExtensions[RegistrationExtensionInputs]) { case (extensionInputs: RegistrationExtensionInputs, authenticatorExtensionOutputs: ObjectNode) =>
              whenever(authenticatorExtensionOutputs.fieldNames().asScala.exists(id => !extensionInputs.getExtensionIds.contains(id))) {
                val steps = finishRegistration(
                  testData = RegistrationTestData.Packed.BasicAttestation.copy(
                    requestedExtensions = extensionInputs
                  ).editAuthenticatorData(
                    authData => new ByteArray(
                      authData.getBytes.updated(32, (authData.getBytes()(32) | 0x80).toByte) ++
                        WebAuthnCodecs.cbor.writeValueAsBytes(authenticatorExtensionOutputs)
                    )
                  )
                )
                val step: FinishRegistrationSteps#Step12 = steps.begin.next.next.next.next.next.next.next.next.next.next.next

                step.validations shouldBe a [Failure[_]]
                step.validations.failed.get shouldBe an [IllegalArgumentException]
                step.tryNext shouldBe a [Failure[_]]
              }
            }
          }

          it("Succeeds if authenticator extensions is a subset of the extensions requested by the Relying Party.") {
            forAll(subsetAuthenticatorExtensions[RegistrationExtensionInputs]) { case (extensionInputs: RegistrationExtensionInputs, authenticatorExtensionOutputs: ObjectNode) =>
              val steps = finishRegistration(
                testData = RegistrationTestData.Packed.BasicAttestation.copy(
                  requestedExtensions = extensionInputs
                ).editAuthenticatorData(
                  authData => new ByteArray(
                    authData.getBytes.updated(32, (authData.getBytes()(32) | 0x80).toByte) ++
                      WebAuthnCodecs.cbor.writeValueAsBytes(authenticatorExtensionOutputs)
                  )
                )
              )
              val step: FinishRegistrationSteps#Step12 = steps.begin.next.next.next.next.next.next.next.next.next.next.next

              step.validations shouldBe a [Success[_]]
              step.tryNext shouldBe a [Success[_]]
            }
          }
        }

      }

      describe("13. Determine the attestation statement format by performing a USASCII case-sensitive match on fmt against the set of supported WebAuthn Attestation Statement Format Identifier values. An up-to-date list of registered WebAuthn Attestation Statement Format Identifier values is maintained in the IANA registry of the same name [WebAuthn-Registries].") {
        def setup(format: String): FinishRegistrationSteps = {
          finishRegistration(
            testData = RegistrationTestData.FidoU2f.BasicAttestation.editAttestationObject("fmt", format)
          )
        }

        def checkUnknown(format: String): Unit = {
          it(s"""Returns no known attestation statement verifier if fmt is "${format}".""") {
            val steps = setup(format)
            val step: FinishRegistrationSteps#Step13 = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next

            step.validations shouldBe a [Success[_]]
            step.tryNext shouldBe a [Success[_]]
            step.format should equal (format)
            step.attestationStatementVerifier.asScala shouldBe empty
          }
        }

        def checkKnown(format: String): Unit = {
          it(s"""Returns a known attestation statement verifier if fmt is "${format}".""") {
            val steps = setup(format)
            val step: FinishRegistrationSteps#Step13 = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next

            step.validations shouldBe a [Success[_]]
            step.tryNext shouldBe a [Success[_]]
            step.format should equal (format)
            step.attestationStatementVerifier.asScala should not be empty
          }
        }

        checkKnown("android-safetynet")
        checkKnown("fido-u2f")
        checkKnown("none")
        checkKnown("packed")

        checkUnknown("android-key")
        checkUnknown("tpm")

        checkUnknown("FIDO-U2F")
        checkUnknown("Fido-U2F")
        checkUnknown("bleurgh")
      }

      describe("14. Verify that attStmt is a correct attestation statement, conveying a valid attestation signature, by using the attestation statement format fmt’s verification procedure given attStmt, authData and the hash of the serialized client data computed in step 7.") {

        describe("If allowUntrustedAttestation is set,") {
          it("a fido-u2f attestation is still rejected if invalid.") {
            val testData = RegistrationTestData.FidoU2f.BasicAttestation.editAttestationObject("attStmt", { attStmtNode: JsonNode =>
              attStmtNode.asInstanceOf[ObjectNode]
                .set("sig", jsonFactory.binaryNode(Array(0, 0, 0, 0)))
            })
            val steps = finishRegistration(
              testData = testData,
              allowUntrustedAttestation = true
            )
            val step: FinishRegistrationSteps#Step14 = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next

            step.validations shouldBe a [Failure[_]]
            step.validations.failed.get.getCause shouldBe a [SignatureException]
            step.tryNext shouldBe a [Failure[_]]
          }
        }

        describe("For the fido-u2f statement format,") {
          it("the default test case is a valid basic attestation.") {
            val steps = finishRegistration(testData = RegistrationTestData.FidoU2f.BasicAttestation)
            val step: FinishRegistrationSteps#Step14 = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next

            step.validations shouldBe a [Success[_]]
            step.attestationType should equal (AttestationType.BASIC)
            step.tryNext shouldBe a [Success[_]]
          }

          it("a test case with self attestation is valid.") {
            val steps = finishRegistration(testData = RegistrationTestData.FidoU2f.SelfAttestation)
            val step: FinishRegistrationSteps#Step14 = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next

            step.validations shouldBe a [Success[_]]
            step.attestationType should equal (AttestationType.SELF_ATTESTATION)
            step.tryNext shouldBe a [Success[_]]
          }

          it("a test case with different signed client data is not valid.") {
            val testData = RegistrationTestData.FidoU2f.SelfAttestation
            val steps = finishRegistration(testData = RegistrationTestData.FidoU2f.BasicAttestation)
            val step: FinishRegistrationSteps#Step14 = new steps.Step14(
              new BouncyCastleCrypto().hash(new ByteArray(testData.clientDataJsonBytes.getBytes.updated(20, (testData.clientDataJsonBytes.getBytes()(20) + 1).toByte))),
              new AttestationObject(testData.attestationObject),
              Some(new FidoU2fAttestationStatementVerifier).asJava,
              Nil.asJava
            )

            step.validations shouldBe a [Failure[_]]
            step.validations.failed.get shouldBe an [IllegalArgumentException]
            step.tryNext shouldBe a [Failure[_]]
          }

          def checkByteFlipFails(index: Int): Unit = {
            val testData = RegistrationTestData.FidoU2f.BasicAttestation.editAuthenticatorData { flipByte(index, _) }

            val steps = finishRegistration(
              testData = testData,
              credentialId = Some(new ByteArray(Array.fill(16)(0)))
            )
            val step: FinishRegistrationSteps#Step14 = new steps.Step14(
              new BouncyCastleCrypto().hash(testData.clientDataJsonBytes),
              new AttestationObject(testData.attestationObject),
              Some(new FidoU2fAttestationStatementVerifier).asJava,
              Nil.asJava
            )

            step.validations shouldBe a [Failure[_]]
            step.validations.failed.get shouldBe an [IllegalArgumentException]
            step.tryNext shouldBe a [Failure[_]]
          }

          it("a test case with a different signed RP ID hash is not valid.") {
            checkByteFlipFails(0)
          }

          it("a test case with a different signed credential ID is not valid.") {
            checkByteFlipFails(32 + 1 + 4 + 16 + 2 + 1)
          }

          it("a test case with a different signed credential public key is not valid.") {
            val testData = RegistrationTestData.FidoU2f.BasicAttestation.editAuthenticatorData { authenticatorData =>
              val decoded = new AuthenticatorData(authenticatorData)
              val L = decoded.getAttestedCredentialData.get.getCredentialId.getBytes.length
              val evilPublicKey: Array[Byte] = decoded.getAttestedCredentialData.get.getCredentialPublicKey.getBytes.updated(30, 0: Byte)

              new ByteArray(authenticatorData.getBytes.take(32 + 1 + 4 + 16 + 2 + L) ++ evilPublicKey)
            }
            val steps = finishRegistration(
              testData = testData,
              credentialId = Some(new ByteArray(Array.fill(16)(0)))
            )
            val step: FinishRegistrationSteps#Step14 = new steps.Step14(
              new BouncyCastleCrypto().hash(testData.clientDataJsonBytes),
              new AttestationObject(testData.attestationObject),
              Some(new FidoU2fAttestationStatementVerifier).asJava,
              Nil.asJava
            )

            step.validations shouldBe a [Failure[_]]
            step.validations.failed.get shouldBe an [IllegalArgumentException]
            step.tryNext shouldBe a [Failure[_]]
          }

          describe("if x5c is not a certificate for an ECDSA public key over the P-256 curve, stop verification and return an error.") {
            val testAuthenticator = TestAuthenticator

            def checkRejected(keypair: KeyPair): Unit = {
              val (credential, _) = testAuthenticator.createBasicAttestedCredential(attestationCertAndKey = Some(testAuthenticator.generateAttestationCertificate(keypair)))

              val steps = finishRegistration(
                testData = RegistrationTestData(
                  attestationObject = credential.getResponse.getAttestationObject,
                  clientDataJson = new String(credential.getResponse.getClientDataJSON.getBytes, "UTF-8")
                ),
                credentialId = Some(credential.getId)
              )
              val step: FinishRegistrationSteps#Step14 = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next

              val standaloneVerification = Try {
                new FidoU2fAttestationStatementVerifier().verifyAttestationSignature(
                  credential.getResponse.getAttestation,
                  new BouncyCastleCrypto().hash(credential.getResponse.getClientDataJSON)
                )
              }

              step.validations shouldBe a [Failure[_]]
              step.validations.failed.get shouldBe an [IllegalArgumentException]
              step.tryNext shouldBe a [Failure[_]]

              standaloneVerification shouldBe a [Failure[_]]
              standaloneVerification.failed.get shouldBe an [IllegalArgumentException]
            }

            def checkAccepted(keypair: KeyPair): Unit = {
              val (credential, _) = testAuthenticator.createBasicAttestedCredential(attestationCertAndKey = Some(testAuthenticator.generateAttestationCertificate(keypair)))

              val steps = finishRegistration(
                testData = RegistrationTestData(
                  attestationObject = credential.getResponse.getAttestationObject,
                  clientDataJson = new String(credential.getResponse.getClientDataJSON.getBytes, "UTF-8")
                ),
                credentialId = Some(credential.getId)
              )
              val step: FinishRegistrationSteps#Step14 = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next

              val standaloneVerification = Try {
                new FidoU2fAttestationStatementVerifier().verifyAttestationSignature(
                  credential.getResponse.getAttestation,
                  new BouncyCastleCrypto().hash(credential.getResponse.getClientDataJSON)
                )
              }

              step.validations shouldBe a [Success[_]]
              step.tryNext shouldBe a [Success[_]]

              standaloneVerification should equal (Success(true))
            }

            it("An RSA attestation certificate is rejected.") {
              checkRejected(testAuthenticator.generateRsaKeypair())
            }

            it("A secp256r1 attestation certificate is accepted.") {
              checkAccepted(testAuthenticator.generateEcKeypair(curve = "secp256r1"))
            }

            it("A secp256k1 attestation certificate is rejected.") {
              checkRejected(testAuthenticator.generateEcKeypair(curve = "secp256k1"))
            }

            it("A P-256 attestation certificate is accepted.") {
              checkAccepted(testAuthenticator.generateEcKeypair(curve = "P-256"))
            }
          }
        }

        describe("For the none statement format,") {
          def flipByte(index: Int, bytes: ByteArray): ByteArray = new ByteArray(bytes.getBytes.updated(index, (0xff ^ bytes.getBytes()(index)).toByte))

          def checkByteFlipSucceeds(mutationDescription: String, index: Int): Unit = {
            it(s"the default test case with mutated ${mutationDescription} is accepted.") {
              val testData = RegistrationTestData.NoneAttestation.Default.editAuthenticatorData {
                flipByte(index, _)
              }

              val steps = finishRegistration(testData = testData)
              val step: FinishRegistrationSteps#Step14 = new steps.Step14(
                new BouncyCastleCrypto().hash(testData.clientDataJsonBytes),
                new AttestationObject(testData.attestationObject),
                Some(new NoneAttestationStatementVerifier).asJava,
                Nil.asJava
              )

              step.validations shouldBe a [Success[_]]
              step.attestationType should equal (AttestationType.NONE)
              step.tryNext shouldBe a [Success[_]]
            }
          }

          it("the default test case is accepted.") {
            val steps = finishRegistration(testData = RegistrationTestData.NoneAttestation.Default)
            val step: FinishRegistrationSteps#Step14 = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next

            step.validations shouldBe a [Success[_]]
            step.attestationType should equal (AttestationType.NONE)
            step.tryNext shouldBe a [Success[_]]
          }

          checkByteFlipSucceeds("signature counter", 32 + 1)
          checkByteFlipSucceeds("AAGUID", 32 + 1 + 4)
          checkByteFlipSucceeds("credential ID", 32 + 1 + 4 + 16 + 2)
        }

        describe("For the packed statement format") {
          val verifier = new PackedAttestationStatementVerifier

          it("the attestation statement verifier implementation is PackedAttestationStatementVerifier.") {
            val steps = finishRegistration(testData = RegistrationTestData.Packed.BasicAttestation)
            val step: FinishRegistrationSteps#Step14 = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next

            step.getAttestationStatementVerifier.get shouldBe a [PackedAttestationStatementVerifier]
          }

          describe("the verification procedure is:") {
            describe("1. Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields.") {

              it("Fails if attStmt.sig is a text value.") {
                val testData = RegistrationTestData.Packed.BasicAttestation
                  .editAttestationObject("attStmt", jsonFactory.objectNode().set("sig", jsonFactory.textNode("foo")))

                val result: Try[Boolean] = Try(verifier.verifyAttestationSignature(
                  new AttestationObject(testData.attestationObject),
                  testData.clientDataJsonHash
                ))

                result shouldBe a [Failure[_]]
                result.failed.get shouldBe an [IllegalArgumentException]
              }

              it("Fails if attStmt.sig is missing.") {
                val testData = RegistrationTestData.Packed.BasicAttestation
                  .editAttestationObject("attStmt", jsonFactory.objectNode().set("x5c", jsonFactory.arrayNode()))

                val result: Try[Boolean] = Try(verifier.verifyAttestationSignature(
                  new AttestationObject(testData.attestationObject),
                  testData.clientDataJsonHash
                ))

                result shouldBe a [Failure[_]]
                result.failed.get shouldBe an [IllegalArgumentException]
              }
            }

            describe("2. If x5c is present, this indicates that the attestation type is not ECDAA. In this case:") {
              it("The attestation type is identified as Basic.") {
                val steps = finishRegistration(testData = RegistrationTestData.Packed.BasicAttestation)
                val step: FinishRegistrationSteps#Step14 = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next

                step.validations shouldBe a [Success[_]]
                step.tryNext shouldBe a [Success[_]]
                step.attestationType should be (AttestationType.BASIC)
              }

              describe("1. Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using the attestation public key in attestnCert with the algorithm specified in alg.") {
                it("Succeeds for the default test case.") {
                  val testData = RegistrationTestData.Packed.BasicAttestation
                  val result: Try[Boolean] = Try(verifier.verifyAttestationSignature(
                    new AttestationObject(testData.attestationObject),
                    testData.clientDataJsonHash
                  ))
                  result should equal (Success(true))
                }

                it("Fail if the default test case is mutated.") {
                  val testData = RegistrationTestData.Packed.BasicAttestation

                  val result: Try[Boolean] = Try(verifier.verifyAttestationSignature(
                    new AttestationObject(
                      testData
                        .editAuthenticatorData({ authData: ByteArray =>
                          new ByteArray(authData.getBytes.updated(16, if (authData.getBytes()(16) == 0) 1: Byte else 0: Byte))
                        })
                        .attestationObject
                    ),
                    testData.clientDataJsonHash
                  ))
                  result should equal (Success(false))
                }
              }

              describe("2. Verify that attestnCert meets the requirements in §8.2.1 Packed Attestation Statement Certificate Requirements.") {
                it("Fails for an attestation signature with an invalid country code.") {
                  val authenticator = TestAuthenticator
                  val (badCert, key): (X509Certificate, PrivateKey) = authenticator.generateAttestationCertificate(
                    name = new X500Name("O=Yubico, C=AA, OU=Authenticator Attestation")
                  )
                  val (credential, _) = authenticator.createBasicAttestedCredential(
                    attestationCertAndKey = Some(badCert, key),
                    attestationStatementFormat = "packed"
                  )
                  val result = Try(verifier.verifyAttestationSignature(credential.getResponse.getAttestation, sha256(credential.getResponse.getClientDataJSON)))

                  result shouldBe a [Failure[_]]
                  result.failed.get shouldBe an [IllegalArgumentException]
                }

                it("succeeds for the default test case.") {
                  val testData = RegistrationTestData.Packed.BasicAttestation
                  val result = verifier.verifyAttestationSignature(
                    new AttestationObject(testData.attestationObject),
                    testData.clientDataJsonHash
                  )
                  result should equal (true)
                }
              }

              describe("3. If attestnCert contains an extension with OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) verify that the value of this extension matches the aaguid in authenticatorData.") {
                it("Succeeds for the default test case.") {
                  val testData = RegistrationTestData.Packed.BasicAttestation
                  val result = verifier.verifyAttestationSignature(
                    new AttestationObject(testData.attestationObject),
                    testData.clientDataJsonHash
                  )

                  testData.packedAttestationCert.getNonCriticalExtensionOIDs.asScala should equal (Set("1.3.6.1.4.1.45724.1.1.4"))
                  result should equal (true)
                }

                it("Succeeds if the attestation certificate does not have the extension.") {
                  val testData = RegistrationTestData.Packed.BasicAttestationWithoutAaguidExtension

                  val result = verifier.verifyAttestationSignature(
                    new AttestationObject(testData.attestationObject),
                    testData.clientDataJsonHash
                  )

                  testData.packedAttestationCert.getNonCriticalExtensionOIDs shouldBe null
                  result should equal (true)
                }

                it("Fails if the attestation certificate has the extension and it does not match the AAGUID.") {
                  val testData = RegistrationTestData.Packed.BasicAttestationWithWrongAaguidExtension

                  val result = Try(verifier.verifyAttestationSignature(
                    new AttestationObject(testData.attestationObject),
                    testData.clientDataJsonHash
                  ))

                  testData.packedAttestationCert.getNonCriticalExtensionOIDs should not be empty
                  result shouldBe a [Failure[_]]
                  result.failed.get shouldBe an [IllegalArgumentException]
                }
              }

              describe("4. Optionally, inspect x5c and consult externally provided knowledge to determine whether attStmt conveys a Basic or AttCA attestation.") {
                it("Nothing to test.") {}
              }

              it("5. If successful, return implementation-specific values representing attestation type Basic, AttCA or uncertainty, and attestation trust path x5c.") {
                val testData = RegistrationTestData.Packed.BasicAttestation
                val steps = finishRegistration(testData = testData)
                val step: FinishRegistrationSteps#Step14 = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next

                step.validations shouldBe a [Success[_]]
                step.tryNext shouldBe a [Success[_]]
                step.attestationType should be (AttestationType.BASIC)
                step.attestationTrustPath.asScala should not be empty
                step.attestationTrustPath.get.asScala should be (List(testData.packedAttestationCert))
              }
            }

            describe("3. If ecdaaKeyId is present, then the attestation type is ECDAA. In this case:") {
              ignore("1. Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using ECDAA-Verify with ECDAA-Issuer public key identified by ecdaaKeyId (see [FIDOEcdaaAlgorithm]).") {
                fail("Test not implemented.")
              }

              ignore("2. If successful, return implementation-specific values representing attestation type ECDAA and attestation trust path ecdaaKeyId.") {
                fail("Test not implemented.")
              }
            }

            describe("4. If neither x5c nor ecdaaKeyId is present, self attestation is in use.") {
              val testDataBase = RegistrationTestData.Packed.SelfAttestation

              it("The attestation type is identified as SelfAttestation.") {
                val steps = finishRegistration(testData = testDataBase)
                val step: FinishRegistrationSteps#Step14 = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next

                step.validations shouldBe a [Success[_]]
                step.tryNext shouldBe a [Success[_]]
                step.attestationType should be (AttestationType.SELF_ATTESTATION)
              }

              describe("1. Validate that alg matches the algorithm of the credentialPublicKey in authenticatorData.") {
                it("Succeeds for the default test case.") {
                  val result = verifier.verifyAttestationSignature(
                    new AttestationObject(testDataBase.attestationObject),
                    testDataBase.clientDataJsonHash
                  )

                  CBORObject.DecodeFromBytes(new AttestationObject(testDataBase.attestationObject).getAuthenticatorData.getAttestedCredentialData.get.getCredentialPublicKey.getBytes).get(CBORObject.FromObject(3)).AsInt64 should equal (-7)
                  new AttestationObject(testDataBase.attestationObject).getAttestationStatement.get("alg").longValue should equal (-7)
                  result should equal (true)
                }

                it("Fails if the alg is a different value.") {
                  val testData = RegistrationTestData.Packed.SelfAttestationWithWrongAlgValue
                  val result = Try(verifier.verifyAttestationSignature(
                    new AttestationObject(testData.attestationObject),
                    testData.clientDataJsonHash
                  ))

                  CBORObject.DecodeFromBytes(new AttestationObject(testData.attestationObject).getAuthenticatorData.getAttestedCredentialData.get.getCredentialPublicKey.getBytes).get(CBORObject.FromObject(3)).AsInt64 should equal (-7)
                  new AttestationObject(testData.attestationObject).getAttestationStatement.get("alg").longValue should equal (-257)
                  result shouldBe a [Failure[_]]
                  result.failed.get shouldBe an [IllegalArgumentException]
                }
              }

              describe("2. Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using the credential public key with alg.") {
                it("Succeeds for the default test case.") {
                  val result = verifier.verifyAttestationSignature(
                    new AttestationObject(testDataBase.attestationObject),
                    testDataBase.clientDataJsonHash
                  )
                  result should equal (true)
                }

                it("Fails if the attestation object is mutated.") {
                  val testData = testDataBase.editAuthenticatorData { authData: ByteArray => new ByteArray(authData.getBytes.updated(16, if (authData.getBytes()(16) == 0) 1: Byte else 0: Byte)) }
                  val result = verifier.verifyAttestationSignature(
                    new AttestationObject(testData.attestationObject),
                    testData.clientDataJsonHash
                  )
                  result should equal (false)
                }

                it("Fails if the client data is mutated.") {
                  val result = verifier.verifyAttestationSignature(
                    new AttestationObject(testDataBase.attestationObject),
                    sha256(new ByteArray(testDataBase.clientDataJson.updated(4, 'ä').getBytes("UTF-8")))
                  )
                  result should equal (false)
                }

                it("Fails if the client data hash is mutated.") {
                  val result = verifier.verifyAttestationSignature(
                    new AttestationObject(testDataBase.attestationObject),
                    new ByteArray(testDataBase.clientDataJsonHash.getBytes.updated(7, if (testDataBase.clientDataJsonHash.getBytes()(7) == 0) 1: Byte else 0: Byte)))
                  result should equal (false)
                }
              }

              it("3. If successful, return implementation-specific values representing attestation type Self and an empty attestation trust path.") {
                val testData = RegistrationTestData.Packed.SelfAttestation
                val steps = finishRegistration(testData = testData)
                val step: FinishRegistrationSteps#Step14 = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next

                step.validations shouldBe a [Success[_]]
                step.tryNext shouldBe a [Success[_]]
                step.attestationType should be (AttestationType.SELF_ATTESTATION)
                step.attestationTrustPath.asScala shouldBe empty
              }
            }
          }

          describe("8.2.1. Packed Attestation Statement Certificate Requirements") {
            val testDataBase = RegistrationTestData.Packed.BasicAttestation

            describe("The attestation certificate MUST have the following fields/extensions:") {
              it("Version MUST be set to 3 (which is indicated by an ASN.1 INTEGER with value 2).") {
                val badCert = Mockito.mock(classOf[X509Certificate])
                val principal = new X500Principal("O=Yubico, C=SE, OU=Authenticator Attestation")
                Mockito.when(badCert.getVersion) thenReturn 2
                Mockito.when(badCert.getSubjectX500Principal) thenReturn principal
                Mockito.when(badCert.getBasicConstraints) thenReturn -1
                val result = Try(verifier.verifyX5cRequirements(badCert, testDataBase.aaguid))

                result shouldBe a [Failure[_]]
                result.failed.get shouldBe an [IllegalArgumentException]

                verifier.verifyX5cRequirements(testDataBase.packedAttestationCert, testDataBase.aaguid) should equal (true)
              }

              describe("Subject field MUST be set to:") {
                it("Subject-C: ISO 3166 code specifying the country where the Authenticator vendor is incorporated (PrintableString)") {
                  val badCert: X509Certificate = TestAuthenticator.generateAttestationCertificate(
                    name = new X500Name("O=Yubico, C=AA, OU=Authenticator Attestation")
                  )._1
                  val result = Try(verifier.verifyX5cRequirements(badCert, testDataBase.aaguid))

                  result shouldBe a [Failure[_]]
                  result.failed.get shouldBe an [IllegalArgumentException]

                  verifier.verifyX5cRequirements(testDataBase.packedAttestationCert, testDataBase.aaguid) should equal (true)
                }

                it("Subject-O: Legal name of the Authenticator vendor (UTF8String)") {
                  val badCert: X509Certificate = TestAuthenticator.generateAttestationCertificate(
                    name = new X500Name("C=SE, OU=Authenticator Attestation")
                  )._1
                  val result = Try(verifier.verifyX5cRequirements(badCert, testDataBase.aaguid))

                  result shouldBe a [Failure[_]]
                  result.failed.get shouldBe an [IllegalArgumentException]

                  verifier.verifyX5cRequirements(testDataBase.packedAttestationCert, testDataBase.aaguid) should equal(true)
                }

                it("""Subject-OU: Literal string "Authenticator Attestation" (UTF8String)""") {
                  val badCert: X509Certificate = TestAuthenticator.generateAttestationCertificate(
                    name = new X500Name("O=Yubico, C=SE, OU=Foo")
                  )._1
                  val result = Try(verifier.verifyX5cRequirements(badCert, testDataBase.aaguid))

                  result shouldBe a [Failure[_]]
                  result.failed.get shouldBe an [IllegalArgumentException]

                  verifier.verifyX5cRequirements(testDataBase.packedAttestationCert, testDataBase.aaguid) should equal(true)
                }

                describe("Subject-CN: A UTF8String of the vendor’s choosing") {
                  it("Nothing to test") {}
                }
              }

              it("If the related attestation root certificate is used for multiple authenticator models, the Extension OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) MUST be present, containing the AAGUID as a 16-byte OCTET STRING. The extension MUST NOT be marked as critical.") {
                val idFidoGenCeAaguid = "1.3.6.1.4.1.45724.1.1.4"

                val badCert: X509Certificate = TestAuthenticator.generateAttestationCertificate(
                  name = new X500Name("O=Yubico, C=SE, OU=Authenticator Attestation"),
                  extensions = List((idFidoGenCeAaguid, false, new DEROctetString(Array[Byte](0, 1, 2, 3))))
                )._1
                val result = Try(verifier.verifyX5cRequirements(badCert, testDataBase.aaguid))

                result shouldBe a [Failure[_]]
                result.failed.get shouldBe an [IllegalArgumentException]

                val badCertCritical: X509Certificate = TestAuthenticator.generateAttestationCertificate(
                  name = new X500Name("O=Yubico, C=SE, OU=Authenticator Attestation"),
                  extensions = List((idFidoGenCeAaguid, true, new DEROctetString(testDataBase.aaguid.getBytes)))
                )._1
                val resultCritical = Try(verifier.verifyX5cRequirements(badCertCritical, testDataBase.aaguid))

                resultCritical shouldBe a [Failure[_]]
                resultCritical.failed.get shouldBe an [IllegalArgumentException]

                val goodCert: X509Certificate = TestAuthenticator.generateAttestationCertificate(
                  name = new X500Name("O=Yubico, C=SE, OU=Authenticator Attestation"),
                  extensions = Nil
                )._1
                val goodResult = Try(verifier.verifyX5cRequirements(badCert, testDataBase.aaguid))

                goodResult shouldBe a [Failure[_]]
                goodResult.failed.get shouldBe an [IllegalArgumentException]

                verifier.verifyX5cRequirements(testDataBase.packedAttestationCert, testDataBase.aaguid) should equal(true)
              }

              it("The Basic Constraints extension MUST have the CA component set to false.") {
                val result = Try(verifier.verifyX5cRequirements(testDataBase.attestationCaCert.get, testDataBase.aaguid))

                result shouldBe a [Failure[_]]
                result.failed.get shouldBe an [IllegalArgumentException]

                verifier.verifyX5cRequirements(testDataBase.packedAttestationCert, testDataBase.aaguid) should equal (true)
              }

              describe("An Authority Information Access (AIA) extension with entry id-ad-ocsp and a CRL Distribution Point extension [RFC5280] are both OPTIONAL as the status of many attestation certificates is available through authenticator metadata services. See, for example, the FIDO Metadata Service [FIDOMetadataService].") {
                it("Nothing to test.") {}
              }
            }
          }
        }

        ignore("The tpm statement format is supported.") {
          val steps = finishRegistration(testData = RegistrationTestData.Tpm.PrivacyCa)
          val step: FinishRegistrationSteps#Step14 = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next

          step.validations shouldBe a [Success[_]]
          step.tryNext shouldBe a [Success[_]]
        }

        ignore("The android-key statement format is supported.") {
          val steps = finishRegistration(testData = RegistrationTestData.AndroidKey.BasicAttestation)
          val step: FinishRegistrationSteps#Step14 = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next

          step.validations shouldBe a [Success[_]]
          step.tryNext shouldBe a [Success[_]]
        }

        describe("For the android-safetynet attestation statement format") {
          val verifier = new AndroidSafetynetAttestationStatementVerifier
          val testDataContainer = RegistrationTestData.AndroidSafetynet
          val defaultTestData = testDataContainer.BasicAttestation

          it("the attestation statement verifier implementation is AndroidSafetynetAttestationStatementVerifier.") {
            val steps = finishRegistration(
              testData = defaultTestData,
              allowUntrustedAttestation = false,
              rp = defaultTestData.rpId
            )
            val step: FinishRegistrationSteps#Step14 = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next

            step.getAttestationStatementVerifier.get shouldBe an [AndroidSafetynetAttestationStatementVerifier]
          }

          describe("the verification procedure is:") {
            def checkFails(testData: RegistrationTestData): Unit = {
              val result: Try[Boolean] = Try(verifier.verifyAttestationSignature(
                new AttestationObject(testData.attestationObject),
                testData.clientDataJsonHash
              ))

              result shouldBe a [Failure[_]]
              result.failed.get shouldBe an [IllegalArgumentException]
            }

            describe("1. Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract the contained fields.") {
              it("Fails if attStmt.ver is a number value.") {
                val testData = defaultTestData
                  .editAttestationObject("attStmt", attStmt => attStmt.asInstanceOf[ObjectNode].set("ver", jsonFactory.numberNode(123)))
                checkFails(testData)
              }

              it("Fails if attStmt.ver is missing.") {
                val testData = defaultTestData
                  .editAttestationObject("attStmt", attStmt => attStmt.asInstanceOf[ObjectNode].without("ver"))
                checkFails(testData)
              }

              it("Fails if attStmt.response is a text value.") {
                val testData = defaultTestData
                  .editAttestationObject("attStmt", attStmt => attStmt.asInstanceOf[ObjectNode].set("response", jsonFactory.textNode(new ByteArray(attStmt.get("response").binaryValue()).getBase64Url)))
                checkFails(testData)
              }

              it("Fails if attStmt.response is missing.") {
                val testData = defaultTestData
                  .editAttestationObject("attStmt", attStmt => attStmt.asInstanceOf[ObjectNode].without("response"))
                checkFails(testData)
              }
            }

            describe("2. Verify that response is a valid SafetyNet response of version ver.") {
              it("Fails if there's a difference in the signature.") {
                val testData = defaultTestData
                  .editAttestationObject("attStmt", attStmt => attStmt.asInstanceOf[ObjectNode].set("response", jsonFactory.binaryNode(editByte(new ByteArray(attStmt.get("response").binaryValue()), 2000, b => ((b + 1) % 26 + 0x41).toByte).getBytes)))

                val result: Try[Boolean] = Try(verifier.verifyAttestationSignature(
                  new AttestationObject(testData.attestationObject),
                  testData.clientDataJsonHash
                ))

                result shouldBe a [Success[_]]
                result.get should be (false)
              }
            }

            describe("3. Verify that the nonce in the response is identical to the Base64 encoding of the SHA-256 hash of the concatenation of authenticatorData and clientDataHash.") {
              it("Fails if an additional property is added to the client data.") {
                val testData = defaultTestData.editClientData("foo", "bar")
                checkFails(testData)
              }
            }

            describe("4. Let attestationCert be the attestation certificate.") {
              it("Nothing to test.") {}
            }

            it("5. Verify that attestationCert is issued to the hostname \"attest.android.com\" (see SafetyNet online documentation).") {
              checkFails(testDataContainer.WrongHostname)
            }

            it("6. Verify that the ctsProfileMatch attribute in the payload of response is true.") {
              checkFails(testDataContainer.FalseCtsProfileMatch)
            }

            describe("7. If successful, return implementation-specific values representing attestation type Basic and attestation trust path attestationCert.") {
              it("The real example succeeds.") {
                val steps = finishRegistration(
                  testData = testDataContainer.RealExample,
                  rp = testDataContainer.RealExample.rpId
                )
                val step: FinishRegistrationSteps#Step14 = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next

                step.validations shouldBe a [Success[_]]
                step.tryNext shouldBe a [Success[_]]
                step.attestationType() should be (AttestationType.BASIC)
                step.attestationTrustPath().get should not be empty
                step.attestationTrustPath().get.size should be (2)
              }

              it("The default test case succeeds.") {
                val steps = finishRegistration(testData = testDataContainer.BasicAttestation)
                val step: FinishRegistrationSteps#Step14 = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next

                step.validations shouldBe a [Success[_]]
                step.tryNext shouldBe a [Success[_]]
                step.attestationType() should be (AttestationType.BASIC)
                step.attestationTrustPath().get should not be empty
                step.attestationTrustPath().get.size should be (1)
              }
            }
          }
        }

        it("The android-safetynet statement format is supported.") {
          val steps = finishRegistration(
            testData = RegistrationTestData.AndroidSafetynet.RealExample,
            rp = RelyingPartyIdentity.builder().id("demo.yubico.com").name("").build()
          )
          val step: FinishRegistrationSteps#Step14 = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next

          step.validations shouldBe a [Success[_]]
          step.tryNext shouldBe a [Success[_]]
        }

        it("Unknown attestation statement formats fail.") {
          val steps = finishRegistration(testData = RegistrationTestData.FidoU2f.BasicAttestation.editAttestationObject("fmt", "urgel"))
          val step: FinishRegistrationSteps#Step14 = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next

          step.validations shouldBe a [Failure[_]]
          step.validations.failed.get shouldBe an [IllegalArgumentException]
          step.tryNext shouldBe a [Failure[_]]
        }

      }

      describe("15. If validation is successful, obtain a list of acceptable trust anchors (attestation root certificates or ECDAA-Issuer public keys) for that attestation type and attestation statement format fmt, from a trusted source or from policy. For example, the FIDO Metadata Service [FIDOMetadataService] provides one way to obtain such information, using the aaguid in the attestedCredentialData in authData.") {

        describe("For the android-safetynet statement format") {
          it("a trust resolver is returned.") {
            val metadataService: MetadataService = new TestMetadataService()
            val steps = finishRegistration(
              testData = RegistrationTestData.AndroidSafetynet.RealExample,
              metadataService = Some(metadataService),
              rp = RegistrationTestData.AndroidSafetynet.RealExample.rpId
            )
            val step: FinishRegistrationSteps#Step15 = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next

            step.validations shouldBe a [Success[_]]
            step.trustResolver.get should not be null
            step.tryNext shouldBe a [Success[_]]
          }
        }

        describe("For the fido-u2f statement format") {

          it("with self attestation, no trust anchors are returned.") {
            val steps = finishRegistration(testData = RegistrationTestData.FidoU2f.SelfAttestation)
            val step: FinishRegistrationSteps#Step15 = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next

            step.validations shouldBe a [Success[_]]
            step.trustResolver.asScala shouldBe empty
            step.tryNext shouldBe a [Success[_]]
          }

          it("with basic attestation, a trust resolver is returned.") {
            val metadataService: MetadataService = new TestMetadataService()
            val steps = finishRegistration(
              testData = RegistrationTestData.FidoU2f.BasicAttestation,
              metadataService = Some(metadataService)
            )
            val step: FinishRegistrationSteps#Step15 = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next

            step.validations shouldBe a [Success[_]]
            step.trustResolver.get should not be null
            step.tryNext shouldBe a [Success[_]]
          }

        }

        describe("For the none statement format") {
          it("no trust anchors are returned.") {
            val steps = finishRegistration(testData = RegistrationTestData.NoneAttestation.Default)
            val step: FinishRegistrationSteps#Step15 = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next

            step.validations shouldBe a [Success[_]]
            step.trustResolver.asScala shouldBe empty
            step.tryNext shouldBe a [Success[_]]
          }
        }
      }

      describe("16. Assess the attestation trustworthiness using the outputs of the verification procedure in step 14, as follows:") {

        describe("If none attestation was used, check if no attestation is acceptable under Relying Party policy.") {
          describe("The default test case") {
            it("is rejected if untrusted attestation is not allowed.") {
              val steps = finishRegistration(
                testData = RegistrationTestData.NoneAttestation.Default,
                allowUntrustedAttestation = false
              )
              val step: FinishRegistrationSteps#Step16 = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next

              step.validations shouldBe a [Failure[_]]
              step.validations.failed.get shouldBe an [IllegalArgumentException]
              step.attestationTrusted should be (false)
              step.tryNext shouldBe a [Failure[_]]
            }

            it("is accepted if untrusted attestation is allowed.") {
              val steps = finishRegistration(
                testData = RegistrationTestData.NoneAttestation.Default,
                allowUntrustedAttestation = true
              )
              val step: FinishRegistrationSteps#Step16 = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next

              step.validations shouldBe a [Success[_]]
              step.attestationTrusted should be (false)
              step.tryNext shouldBe a [Success[_]]
            }
          }
        }

        describe("If self attestation was used, check if self attestation is acceptable under Relying Party policy.") {

          describe("The default test case, with self attestation,") {
            it("is rejected if untrusted attestation is not allowed.") {
              val steps = finishRegistration(
                testData = RegistrationTestData.FidoU2f.SelfAttestation,
                allowUntrustedAttestation = false
              )
              val step: FinishRegistrationSteps#Step16 = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next

              step.validations shouldBe a [Failure[_]]
              step.validations.failed.get shouldBe an [IllegalArgumentException]
              step.attestationTrusted should be (false)
              step.tryNext shouldBe a [Failure[_]]
            }

            it("is accepted if untrusted attestation is allowed.") {
              val steps = finishRegistration(
                testData = RegistrationTestData.FidoU2f.SelfAttestation,
                allowUntrustedAttestation = true
              )
              val step: FinishRegistrationSteps#Step16 = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next

              step.validations shouldBe a [Success[_]]
              step.attestationTrusted should be (false)
              step.tryNext shouldBe a [Success[_]]
            }
          }
        }

        ignore("If ECDAA was used, verify that the identifier of the ECDAA-Issuer public key used is included in the set of acceptable trust anchors obtained in step 15.") {
          fail("Not implemented.")
        }

        describe("Otherwise, use the X.509 certificates returned by the verification procedure to verify that the attestation public key correctly chains up to an acceptable root certificate.") {

          def generateTests(testData: RegistrationTestData): Unit = {
            it("is rejected if untrusted attestation is not allowed and the metadata service does not trust it.") {
              val metadataService: MetadataService = new TestMetadataService()
              val steps = finishRegistration(
                allowUntrustedAttestation = false,
                testData = testData,
                metadataService = Some(metadataService),
                rp = testData.rpId
              )
              val step: FinishRegistrationSteps#Step16 = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next

              step.validations shouldBe a [Failure[_]]
              step.attestationTrusted should be (false)
              step.attestationMetadata.asScala should not be empty
              step.attestationMetadata.get.getMetadataIdentifier.asScala shouldBe empty
              step.tryNext shouldBe a [Failure[_]]
            }

            it("is accepted if untrusted attestation is allowed and the metadata service does not trust it.") {
              val metadataService: MetadataService = new TestMetadataService()
              val steps = finishRegistration(
                allowUntrustedAttestation = true,
                testData = testData,
                metadataService = Some(metadataService),
                rp = testData.rpId
              )
              val step: FinishRegistrationSteps#Step16 = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next

              step.validations shouldBe a [Success[_]]
              step.attestationTrusted should be (false)
              step.attestationMetadata.asScala should not be empty
              step.attestationMetadata.get.getMetadataIdentifier.asScala shouldBe empty
              step.tryNext shouldBe a [Success[_]]
            }

            it("is accepted if the metadata service trusts it.") {
              val metadataService: MetadataService = new TestMetadataService(Some(
                Attestation.builder()
                    .trusted(true)
                    .metadataIdentifier(Some("Test attestation CA").asJava)
                    .build()
                )
              )

              val steps = finishRegistration(
                testData = testData,
                metadataService = Some(metadataService),
                rp = testData.rpId
              )
              val step: FinishRegistrationSteps#Step16 = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next

              step.validations shouldBe a [Success[_]]
              step.attestationTrusted should be (true)
              step.attestationMetadata.asScala should not be empty
              step.attestationMetadata.get.getMetadataIdentifier.asScala should equal (Some("Test attestation CA"))
              step.tryNext shouldBe a [Success[_]]
            }
          }

          describe("An android-key basic attestation") {
            ignore("fails for now.") {
              fail("Test not implemented.")
            }
          }

          describe("An android-safetynet basic attestation") {
            generateTests(testData = RegistrationTestData.AndroidSafetynet.RealExample)
          }

          describe("A fido-u2f basic attestation") {
            generateTests(testData = RegistrationTestData.FidoU2f.BasicAttestation)
          }

          describe("A packed basic attestation") {
            generateTests(testData = RegistrationTestData.Packed.BasicAttestation)
          }
        }

      }

      describe("17. Check that the credentialId is not yet registered to any other user. If registration is requested for a credential that is already registered to a different user, the Relying Party SHOULD fail this registration ceremony, or it MAY decide to accept the registration, e.g. while deleting the older registration.") {

        val testData = RegistrationTestData.FidoU2f.SelfAttestation

        it("Registration is aborted if the given credential ID is already registered.") {
          val credentialRepository = new CredentialRepository {
            override def lookup(id: ByteArray, uh: ByteArray) = Some(
              RegisteredCredential.builder()
                .credentialId(id)
                .userHandle(uh)
                .publicKeyCose(testData.response.getResponse.getAttestation.getAuthenticatorData.getAttestedCredentialData.get.getCredentialPublicKey)
                .signatureCount(1337)
                .build()
            ).asJava

            override def lookupAll(id: ByteArray) = id match {
              case id if id == testData.response.getResponse.getAttestation.getAuthenticatorData.getAttestedCredentialData.get.getCredentialId =>
                Set(
                  RegisteredCredential.builder()
                    .credentialId(id)
                    .userHandle(testData.request.getUser.getId)
                    .publicKeyCose(testData.response.getResponse.getAttestation.getAuthenticatorData.getAttestedCredentialData.get.getCredentialPublicKey)
                    .signatureCount(1337)
                    .build()
                ).asJava
              case _ => Set.empty.asJava
            }
            override def getCredentialIdsForUsername(username: String) = ???
            override def getUserHandleForUsername(username: String): Optional[ByteArray] = ???
            override def getUsernameForUserHandle(userHandle: ByteArray): Optional[String] = ???
          }

          val steps = finishRegistration(
            allowUntrustedAttestation = true,
            testData = testData,
            credentialRepository = Some(credentialRepository)
          )
          val step: FinishRegistrationSteps#Step17 = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next

          step.validations shouldBe a [Failure[_]]
          step.validations.failed.get shouldBe an [IllegalArgumentException]
          step.tryNext shouldBe an [Failure[_]]
        }

        it("Registration proceeds if the given credential ID is not already registered.") {
          val credentialRepository = new CredentialRepository {
            override def lookup(id: ByteArray, uh: ByteArray) = None.asJava
            override def lookupAll(id: ByteArray) = Set.empty.asJava
            override def getCredentialIdsForUsername(username: String) = ???
            override def getUserHandleForUsername(username: String): Optional[ByteArray] = ???
            override def getUsernameForUserHandle(userHandle: ByteArray): Optional[String] = ???
          }

          val steps = finishRegistration(
            allowUntrustedAttestation = true,
            testData = testData,
            credentialRepository = Some(credentialRepository)
          )
          val step: FinishRegistrationSteps#Step17 = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next.next

          step.validations shouldBe a [Success[_]]
          step.tryNext shouldBe a [Success[_]]
        }
      }

      describe("18. If the attestation statement attStmt verified successfully and is found to be trustworthy, then register the new credential with the account that was denoted in the options.user passed to create(), by associating it with the credentialId and credentialPublicKey in the attestedCredentialData in authData, as appropriate for the Relying Party's system.") {
        it("A test case with trusted basic attestation succeeds.") {
          val testData = RegistrationTestData.FidoU2f.BasicAttestation
          val steps = finishRegistration(
            testData = testData,
            metadataService = Some(new TestMetadataService(Some(Attestation.builder().trusted(true).build()))),
            credentialRepository = Some(emptyCredentialRepository)
          )
          steps.run.getKeyId.getId should be (testData.response.getId)
          steps.run.isAttestationTrusted should be (true)
        }
      }

      describe("19. If the attestation statement attStmt successfully verified but is not trustworthy per step 16 above, the Relying Party SHOULD fail the registration ceremony.") {
        it("The test case with self attestation succeeds, but reports attestation is not trusted.") {
          val testData = RegistrationTestData.FidoU2f.SelfAttestation
          val steps = finishRegistration(
            testData = testData,
            allowUntrustedAttestation = true,
            credentialRepository = Some(emptyCredentialRepository)
          )
          steps.run.getKeyId.getId should be (testData.response.getId)
          steps.run.isAttestationTrusted should be (false)
        }

        it("The test case with unknown attestation fails.") {
          val testData = RegistrationTestData.FidoU2f.BasicAttestation.editAttestationObject("fmt", "urgel")
          val steps = finishRegistration(
            testData = testData,
            allowUntrustedAttestation = true,
            credentialRepository = Some(emptyCredentialRepository)
          )
          val result = Try(steps.run)
          result.failed.get shouldBe an [IllegalArgumentException]
        }

        describe("NOTE: However, if permitted by policy, the Relying Party MAY register the credential ID and credential public key but treat the credential as one with self attestation (see §6.4.3 Attestation Types). If doing so, the Relying Party is asserting there is no cryptographic proof that the public key credential has been generated by a particular authenticator model. See [FIDOSecRef] and [UAFProtocol] for a more detailed discussion.") {
          it("Nothing to test.") {}
        }

        def testUntrusted(testData: RegistrationTestData): Unit = {
          val fmt = new AttestationObject(testData.attestationObject).getFormat
          it(s"""A test case with good "${fmt}" attestation but no metadata service succeeds, but reports attestation as not trusted.""") {
            val testData = RegistrationTestData.FidoU2f.BasicAttestation
            val steps = finishRegistration(
              testData = testData,
              metadataService = None,
              allowUntrustedAttestation = true,
              credentialRepository = Some(emptyCredentialRepository)
            )
            steps.run.getKeyId.getId should be (testData.response.getId)
            steps.run.isAttestationTrusted should be (false)
          }
        }

        testUntrusted(RegistrationTestData.AndroidKey.BasicAttestation)
        testUntrusted(RegistrationTestData.AndroidSafetynet.BasicAttestation)
        testUntrusted(RegistrationTestData.FidoU2f.BasicAttestation)
        testUntrusted(RegistrationTestData.NoneAttestation.Default)
        testUntrusted(RegistrationTestData.Tpm.PrivacyCa)
      }

      it("(Deleted) If verification of the attestation statement failed, the Relying Party MUST fail the registration ceremony.") {
        val steps = finishRegistration(testData = RegistrationTestData.FidoU2f.BasicAttestation.editClientData("foo", "bar"))
        val step14: FinishRegistrationSteps#Step14 = steps.begin.next.next.next.next.next.next.next.next.next.next.next.next.next
        val step15: Try[FinishRegistrationSteps#Step15] = Try(step14.next)

        step14.validations shouldBe a [Failure[_]]
        Try(step14.next) shouldBe a [Failure[_]]

        step15 shouldBe a [Failure[_]]
        step15.failed.get shouldBe an [IllegalArgumentException]

        Try(steps.run) shouldBe a [Failure[_]]
        Try(steps.run).failed.get shouldBe an [IllegalArgumentException]
      }

      describe("The default RelyingParty settings") {

        val rp = RelyingParty.builder()
          .identity(RelyingPartyIdentity.builder().id("localhost").name("Test party").build())
          .credentialRepository(emptyCredentialRepository)
          .build()

        val request = rp.startRegistration(StartRegistrationOptions.builder()
          .user(UserIdentity.builder().name("test").displayName("Test Testsson").id(new ByteArray(Array())).build())
          .build()
        ).toBuilder()
          .challenge(RegistrationTestData.NoneAttestation.Default.clientData.getChallenge)
          .build()

        it("accept registrations with no attestation.") {
          val result = rp.finishRegistration(FinishRegistrationOptions.builder()
              .request(request)
              .response(RegistrationTestData.NoneAttestation.Default.response)
              .build()
          )

          result.isAttestationTrusted should be (false)
          result.getKeyId.getId should equal (RegistrationTestData.NoneAttestation.Default.response.getId)
        }

        it("accept android-key attestations but report they're untrusted.") {
          val result = rp.finishRegistration(FinishRegistrationOptions.builder()
            .request(request)
            .response(RegistrationTestData.AndroidKey.BasicAttestation.response)
            .build()
          )

          result.isAttestationTrusted should be (false)
          result.getKeyId.getId should equal (RegistrationTestData.AndroidKey.BasicAttestation.response.getId)
        }

        it("accept TPM attestations but report they're untrusted.") {
          val result = rp.finishRegistration(FinishRegistrationOptions.builder()
            .request(request)
            .response(RegistrationTestData.Tpm.PrivacyCa.response)
            .build()
          )

          result.isAttestationTrusted should be (false)
          result.getKeyId.getId should equal (RegistrationTestData.Tpm.PrivacyCa.response.getId)
        }

      }

      describe("RelyingParty supports registering") {
        it("a real packed attestation with an RSA key.") {
          val rp = RelyingParty.builder()
            .identity(RelyingPartyIdentity.builder().id("demo3.yubico.test").name("Yubico WebAuthn demo").build())
            .credentialRepository(emptyCredentialRepository)
            .origins(Set("https://demo3.yubico.test:8443").asJava)
            .build()

          val testData = RegistrationTestData.Packed.BasicAttestationRsa
          val result = rp.finishRegistration(FinishRegistrationOptions.builder()
            .request(testData.request)
            .response(testData.response)
            .build()
          )

          result.isAttestationTrusted should be (false)
          result.getKeyId.getId should equal (testData.response.getId)
        }
      }

    }

  }

}
