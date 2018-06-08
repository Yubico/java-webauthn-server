package com.yubico.webauthn.rp

import java.security.MessageDigest
import java.security.KeyPair
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.util.Optional

import com.fasterxml.jackson.core.JsonParseException
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.node.JsonNodeFactory
import com.upokecenter.cbor.CBORObject
import com.yubico.scala.util.JavaConverters._
import com.yubico.u2f.attestation.MetadataResolver
import com.yubico.u2f.attestation.MetadataObject
import com.yubico.u2f.attestation.MetadataService
import com.yubico.u2f.attestation.resolvers.SimpleResolver
import com.yubico.u2f.crypto.BouncyCastleCrypto
import com.yubico.u2f.crypto.Crypto
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding
import com.yubico.webauthn.RelyingParty
import com.yubico.webauthn.FinishRegistrationSteps
import com.yubico.webauthn.CredentialRepository
import com.yubico.webauthn.data.ArrayBuffer
import com.yubico.webauthn.data.RelyingPartyIdentity
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria
import com.yubico.webauthn.data.AttestationObject
import com.yubico.webauthn.data.AuthenticatorData
import com.yubico.webauthn.data.Basic
import com.yubico.webauthn.data.SelfAttestation
import com.yubico.webauthn.data.Discouraged
import com.yubico.webauthn.data.Preferred
import com.yubico.webauthn.data.Required
import com.yubico.webauthn.data.Base64UrlString
import com.yubico.webauthn.data.NoneAttestation
import com.yubico.webauthn.data.RegisteredCredential
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor
import com.yubico.webauthn.impl.FidoU2fAttestationStatementVerifier
import com.yubico.webauthn.impl.PackedAttestationStatementVerifier
import com.yubico.webauthn.impl.NoneAttestationStatementVerifier
import com.yubico.webauthn.test.TestAuthenticator
import com.yubico.webauthn.util.WebAuthnCodecs
import javax.security.auth.x500.X500Principal
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

  private val crypto: Crypto = new BouncyCastleCrypto
  private def sha256(bytes: ArrayBuffer): ArrayBuffer = crypto.hash(bytes.toArray).toVector

  private def finishRegistration(
    allowUntrustedAttestation: Boolean = false,
    callerTokenBindingId: Option[String] = None,
    credentialId: Option[ArrayBuffer] = None,
    credentialRepository: Option[CredentialRepository] = None,
    metadataService: Option[MetadataService] = None,
    rp: RelyingPartyIdentity = RelyingPartyIdentity(name = "Test party", id = "localhost"),
    testData: RegistrationTestData
  ): FinishRegistrationSteps = {
    new RelyingParty(
      allowUntrustedAttestation = allowUntrustedAttestation,
      challengeGenerator = null,
      origins = List(rp.id).asJava,
      preferredPubkeyParams = Nil.asJava,
      rp = rp,
      credentialRepository = credentialRepository getOrElse null,
      metadataService = metadataService.asJava
    )._finishRegistration(testData.request, testData.response, callerTokenBindingId.asJava)
  }

  describe("§7.1. Registering a new credential") {

    describe("When registering a new credential, represented by an AuthenticatorAttestationResponse structure response and an AuthenticationExtensionsClientOutputs structure clientExtensionResults, as part of a registration ceremony, a Relying Party MUST proceed as follows:") {

      describe("1. Let JSONtext be the result of running UTF-8 decode on the value of response.clientDataJSON.") {
        it("Nothing to test.") {}
      }

      describe("2. Let C, the client data claimed as collected during the credential creation, be the result of running an implementation-specific JSON parser on JSONtext.") {

        it("Fails if clientDataJson is not valid JSON.") {
          val steps = finishRegistration(
            testData = RegistrationTestData.FidoU2f.BasicAttestation.copy(
              clientDataJson = "{",
              overrideRequest = Some(RegistrationTestData.FidoU2f.BasicAttestation.request)
            )
          )
          val step: steps.Step2 = steps.begin.next.get

          step.validations shouldBe a [Failure[_]]
          step.validations.failed.get shouldBe a [JsonParseException]
          step.next shouldBe a [Failure[_]]
        }

        it("Succeeds if clientDataJson is valid JSON.") {
          val steps = finishRegistration(
            testData = RegistrationTestData.FidoU2f.BasicAttestation.copy(
              clientDataJson = "{}",
              overrideRequest = Some(RegistrationTestData.FidoU2f.BasicAttestation.request)
            )
          )
          val step: steps.Step2 = steps.begin.next.get

          step.validations shouldBe a [Success[_]]
          step.clientData should not be null
          step.next shouldBe a [Success[_]]
        }
      }

      describe("3. Verify that the value of C.type is webauthn.create.") {
        it("The default test case succeeds.") {
          val steps = finishRegistration(testData = RegistrationTestData.FidoU2f.BasicAttestation)
          val step: steps.Step3 = steps.begin.next.get.next.get

          step.validations shouldBe a [Success[_]]
        }


        def assertFails(typeString: String): Unit = {
          val steps = finishRegistration(
            testData = RegistrationTestData.FidoU2f.BasicAttestation.editClientData("type", typeString)
          )
          val step: steps.Step3 = steps.begin.next.get.next.get

          step.validations shouldBe a [Failure[_]]
          step.validations.failed.get shouldBe an [AssertionError]
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
            overrideRequest = Some(RegistrationTestData.FidoU2f.BasicAttestation.request.copy(challenge = Vector.fill(16)(0: Byte)))
          )
        )
        val step: steps.Step4 = steps.begin.next.get.next.get.next.get

        step.validations shouldBe a [Failure[_]]
        step.validations.failed.get shouldBe an [AssertionError]
        step.next shouldBe a [Failure[_]]
      }

      it("5. Verify that the value of C.origin matches the Relying Party's origin.") {
        val steps = finishRegistration(
          testData = RegistrationTestData.FidoU2f.BasicAttestation.editClientData("origin", "root.evil")
        )
        val step: steps.Step5 = steps.begin.next.get.next.get.next.get.next.get

        step.validations shouldBe a [Failure[_]]
        step.validations.failed.get shouldBe an [AssertionError]
        step.next shouldBe a [Failure[_]]
      }

      describe("6. Verify that the value of C.tokenBinding.status matches the state of Token Binding for the TLS connection over which the assertion was obtained.") {
        it("Verification succeeds if neither side uses token binding ID.") {
          val steps = finishRegistration(testData = RegistrationTestData.FidoU2f.BasicAttestation)
          val step: steps.Step6 = steps.begin.next.get.next.get.next.get.next.get.next.get

          step.validations shouldBe a [Success[_]]
          step.next shouldBe a [Success[_]]
        }

        it("Verification succeeds if client data specifies token binding is unsupported, and RP does not use it.") {
          val steps = finishRegistration(testData = RegistrationTestData.FidoU2f.BasicAttestation
            .editClientData("tokenBinding", toJson(Map("status" -> "not-supported")))
          )
          val step: steps.Step6 = steps.begin.next.get.next.get.next.get.next.get.next.get

          step.validations shouldBe a [Success[_]]
          step.next shouldBe a [Success[_]]
        }

        it("Verification succeeds if client data specifies token binding is supported, and RP does not use it.") {
          val steps = finishRegistration(testData = RegistrationTestData.FidoU2f.BasicAttestation
            .editClientData("tokenBinding", toJson(Map("status" -> "supported")))
          )
          val step: steps.Step6 = steps.begin.next.get.next.get.next.get.next.get.next.get

          step.validations shouldBe a [Success[_]]
          step.next shouldBe a [Success[_]]
        }

        it("Verification fails if client data does not specify token binding status and RP specifies token binding ID.") {
          val steps = finishRegistration(
            callerTokenBindingId = Some("YELLOWSUBMARINE"),
            testData = RegistrationTestData.FidoU2f.BasicAttestation.editClientData(_.without("tokenBinding"))
          )
          val step: steps.Step6 = steps.begin.next.get.next.get.next.get.next.get.next.get

          step.validations shouldBe a [Failure[_]]
          step.validations.failed.get shouldBe an [AssertionError]
          step.next shouldBe a [Failure[_]]
        }

        it("Verification succeeds if client data does not specify token binding status and RP does not specify token binding ID.") {
          val steps = finishRegistration(
            callerTokenBindingId = None,
            testData = RegistrationTestData.FidoU2f.BasicAttestation.editClientData(_.without("tokenBinding"))
          )
          val step: steps.Step6 = steps.begin.next.get.next.get.next.get.next.get.next.get

          step.validations shouldBe a [Success[_]]
          step.next shouldBe a [Success[_]]
        }
        it("Verification fails if client data specifies token binding ID but RP does not.") {
          val steps = finishRegistration(
            callerTokenBindingId = None,
            testData = RegistrationTestData.FidoU2f.BasicAttestation.editClientData("tokenBinding", toJson(Map("status" -> "present", "id" -> "YELLOWSUBMARINE")))
          )
          val step: steps.Step6 = steps.begin.next.get.next.get.next.get.next.get.next.get

          step.validations shouldBe a [Failure[_]]
          step.validations.failed.get shouldBe an [AssertionError]
          step.next shouldBe a [Failure[_]]
        }

        describe("If Token Binding was used on that TLS connection, also verify that C.tokenBinding.id matches the base64url encoding of the Token Binding ID for the connection.") {
          it("Verification succeeds if both sides specify the same token binding ID.") {
            val steps = finishRegistration(
              callerTokenBindingId = Some("YELLOWSUBMARINE"),
              testData = RegistrationTestData.FidoU2f.BasicAttestation.editClientData("tokenBinding", toJson(Map("status" -> "present", "id" -> "YELLOWSUBMARINE")))
            )
            val step: steps.Step6 = steps.begin.next.get.next.get.next.get.next.get.next.get

            step.validations shouldBe a [Success[_]]
            step.next shouldBe a [Success[_]]
          }

          it("Verification fails if ID is missing from tokenBinding in client data.") {
            val steps = finishRegistration(
              callerTokenBindingId = Some("YELLOWSUBMARINE"),
              testData = RegistrationTestData.FidoU2f.BasicAttestation.editClientData("tokenBinding", toJson(Map("status" -> "present")))
            )
            val step: steps.Step6 = steps.begin.next.get.next.get.next.get.next.get.next.get

            step.validations shouldBe a [Failure[_]]
            step.validations.failed.get shouldBe an [AssertionError]
            step.next shouldBe a [Failure[_]]
          }

          it("Verification fails if RP specifies token binding ID but client does not support it.") {
            val steps = finishRegistration(
              callerTokenBindingId = Some("YELLOWSUBMARINE"),
              testData = RegistrationTestData.FidoU2f.BasicAttestation.editClientData("tokenBinding", toJson(Map("status" -> "not-supported")))
            )
            val step: steps.Step6 = steps.begin.next.get.next.get.next.get.next.get.next.get

            step.validations shouldBe a [Failure[_]]
            step.validations.failed.get shouldBe an [AssertionError]
            step.next shouldBe a [Failure[_]]
          }

          it("Verification fails if RP specifies token binding ID but client does not use it.") {
            val steps = finishRegistration(
              callerTokenBindingId = Some("YELLOWSUBMARINE"),
              testData = RegistrationTestData.FidoU2f.BasicAttestation.editClientData("tokenBinding", toJson(Map("status" -> "supported")))
            )
            val step: steps.Step6 = steps.begin.next.get.next.get.next.get.next.get.next.get

            step.validations shouldBe a [Failure[_]]
            step.validations.failed.get shouldBe an [AssertionError]
            step.next shouldBe a [Failure[_]]
          }

          it("Verification fails if client data and RP specify different token binding IDs.") {
            val steps = finishRegistration(
              callerTokenBindingId = Some("ORANGESUBMARINE"),
              testData = RegistrationTestData.FidoU2f.BasicAttestation.editClientData("tokenBinding", toJson(Map("status" -> "supported", "id" -> "YELLOWSUBMARINE")))
            )
            val step: steps.Step6 = steps.begin.next.get.next.get.next.get.next.get.next.get

            step.validations shouldBe a [Failure[_]]
            step.validations.failed.get shouldBe an [AssertionError]
            step.next shouldBe a [Failure[_]]
          }
        }

      }

      it("7. Compute the hash of response.clientDataJSON using SHA-256.") {
        val steps = finishRegistration(testData = RegistrationTestData.FidoU2f.BasicAttestation)
        val step: steps.Step7 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get

        step.validations shouldBe a [Success[_]]
        step.next shouldBe a [Success[_]]
        step.clientDataJsonHash should equal (MessageDigest.getInstance("SHA-256").digest(RegistrationTestData.FidoU2f.BasicAttestation.clientDataJsonBytes.toArray).toVector)
      }

      it("8. Perform CBOR decoding on the attestationObject field of the AuthenticatorAttestationResponse structure to obtain the attestation statement format fmt, the authenticator data authData, and the attestation statement attStmt.") {
        val steps = finishRegistration(testData = RegistrationTestData.FidoU2f.BasicAttestation)
        val step: steps.Step8 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get

        step.validations shouldBe a [Success[_]]
        step.next shouldBe a [Success[_]]
        step.attestation.format should equal ("fido-u2f")
        step.attestation.authenticatorData should not be null
        step.attestation.attestationStatement should not be null
      }

      describe("9. Verify that the RP ID hash in authData is indeed the SHA-256 hash of the RP ID expected by the RP.") {
        it("Fails if RP ID is different.") {
          val steps = finishRegistration(
            testData = RegistrationTestData.FidoU2f.BasicAttestation.editAuthenticatorData { authData: ArrayBuffer =>
              Vector.fill[Byte](32)(0) ++ authData.drop(32)
            }
          )
          val step: steps.Step9 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

          step.validations shouldBe a [Failure[_]]
          step.validations.failed.get shouldBe an [AssertionError]
          step.next shouldBe a [Failure[_]]
        }

        it("Succeeds if RP ID is the same.") {
          val steps = finishRegistration(testData = RegistrationTestData.FidoU2f.BasicAttestation)
          val step: steps.Step9 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

          step.validations shouldBe a [Success[_]]
          step.next shouldBe a [Success[_]]
        }
      }

      describe("10. If user verification is required for this registration, verify that the User Verified bit of the flags in authData is set.") {
        val testData = RegistrationTestData.Packed.BasicAttestation
        val authData = testData.response.response.authenticatorData

        def flagOn(authData: ArrayBuffer): ArrayBuffer = authData.updated(32, (authData(32) | 0x04).toByte)
        def flagOff(authData: ArrayBuffer): ArrayBuffer = authData.updated(32, (authData(32) & 0xfb).toByte)

        it("Succeeds if UV is discouraged and flag is not set.") {
          val steps = finishRegistration(
            testData = testData.copy(
              authenticatorSelection = Some(AuthenticatorSelectionCriteria(userVerification = Discouraged))
            ).editAuthenticatorData(flagOff)
          )
          val step: steps.Step10 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

          step.validations shouldBe a [Success[_]]
          step.next shouldBe a [Success[_]]
        }

        it("Succeeds if UV is discouraged and flag is set.") {
          val steps = finishRegistration(
            testData = testData.copy(
              authenticatorSelection = Some(AuthenticatorSelectionCriteria(userVerification = Discouraged))
            ).editAuthenticatorData(flagOn)
          )
          val step: steps.Step10 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

          step.validations shouldBe a [Success[_]]
          step.next shouldBe a [Success[_]]
        }

        it("Succeeds if UV is preferred and flag is not set.") {
          val steps = finishRegistration(
            testData = testData.copy(
              authenticatorSelection = Some(AuthenticatorSelectionCriteria(userVerification = Preferred))
            ).editAuthenticatorData(flagOff)
          )
          val step: steps.Step10 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

          step.validations shouldBe a [Success[_]]
          step.next shouldBe a [Success[_]]
        }

        it("Succeeds if UV is preferred and flag is set.") {
          val steps = finishRegistration(
            testData = testData.copy(
              authenticatorSelection = Some(AuthenticatorSelectionCriteria(userVerification = Preferred))
            ).editAuthenticatorData(flagOn)
          )
          val step: steps.Step10 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

          step.validations shouldBe a [Success[_]]
          step.next shouldBe a [Success[_]]
        }

        it("Fails if UV is required and flag is not set.") {
          val steps = finishRegistration(
            testData = testData.copy(
              authenticatorSelection = Some(AuthenticatorSelectionCriteria(userVerification = Required))
            ).editAuthenticatorData(flagOff)
          )
          val step: steps.Step10 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

          step.validations shouldBe a [Failure[_]]
          step.validations.failed.get shouldBe an [AssertionError]
          step.next shouldBe a [Failure[_]]
        }

        it("Succeeds if UV is required and flag is set.") {
          val steps = finishRegistration(
            testData = testData.copy(
              authenticatorSelection = Some(AuthenticatorSelectionCriteria(userVerification = Required))
            ).editAuthenticatorData(flagOn)
          )
          val step: steps.Step10 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

          step.validations shouldBe a [Success[_]]
          step.next shouldBe a [Success[_]]
        }
      }

      describe("11. If user verification is not required for this registration, verify that the User Present bit of the flags in authData is set.") {
        val testData = RegistrationTestData.Packed.BasicAttestation
        val authData = testData.response.response.authenticatorData

        def flagOn(authData: ArrayBuffer): ArrayBuffer = authData.updated(32, (authData(32) | 0x04 | 0x01).toByte)
        def flagOff(authData: ArrayBuffer): ArrayBuffer = authData.updated(32, ((authData(32) | 0x04) & 0xfe).toByte)

        it("Fails if UV is discouraged and flag is not set.") {
          val steps = finishRegistration(
            testData = testData.copy(
              authenticatorSelection = Some(AuthenticatorSelectionCriteria(userVerification = Discouraged))
            ).editAuthenticatorData(flagOff)
          )
          val step: steps.Step11 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

          step.validations shouldBe a [Failure[_]]
          step.validations.failed.get shouldBe an [AssertionError]
          step.next shouldBe a [Failure[_]]
        }

        it("Succeeds if UV is discouraged and flag is set.") {
          val steps = finishRegistration(
            testData = testData.copy(
              authenticatorSelection = Some(AuthenticatorSelectionCriteria(userVerification = Discouraged))
            ).editAuthenticatorData(flagOn)
          )
          val step: steps.Step11 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

          step.validations shouldBe a [Success[_]]
          step.next shouldBe a [Success[_]]
        }

        it("Fails if UV is preferred and flag is not set.") {
          val steps = finishRegistration(
            testData = testData.copy(
              authenticatorSelection = Some(AuthenticatorSelectionCriteria(userVerification = Preferred))
            ).editAuthenticatorData(flagOff)
          )
          val step: steps.Step11 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

          step.validations shouldBe a [Failure[_]]
          step.validations.failed.get shouldBe an [AssertionError]
          step.next shouldBe a [Failure[_]]
        }

        it("Succeeds if UV is preferred and flag is set.") {
          val steps = finishRegistration(
            testData = testData.copy(
              authenticatorSelection = Some(AuthenticatorSelectionCriteria(userVerification = Preferred))
            ).editAuthenticatorData(flagOn)
          )
          val step: steps.Step11 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

          step.validations shouldBe a [Success[_]]
          step.next shouldBe a [Success[_]]
        }

        it("Succeeds if UV is required and flag is not set.") {
          val steps = finishRegistration(
            testData = testData.copy(
              authenticatorSelection = Some(AuthenticatorSelectionCriteria(userVerification = Required))
            ).editAuthenticatorData(flagOff)
          )
          val step: steps.Step11 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

          step.validations shouldBe a [Success[_]]
          step.next shouldBe a [Success[_]]
        }

        it("Succeeds if UV is required and flag is set.") {
          val steps = finishRegistration(
            testData = testData.copy(
              authenticatorSelection = Some(AuthenticatorSelectionCriteria(userVerification = Required))
            ).editAuthenticatorData(flagOn)
          )
          val step: steps.Step11 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

          step.validations shouldBe a [Success[_]]
          step.next shouldBe a [Success[_]]
        }
      }

      describe("12. Verify that the values of the ") {

        describe("client extension outputs in clientExtensionResults are as expected, considering the client extension input values that were given as the extensions option in the create() call. In particular, any extension identifier values in the clientExtensionResults MUST be also be present as extension identifier values in the extensions member of options, i.e., no extensions are present that were not requested. In the general case, the meaning of \"are as expected\" is specific to the Relying Party and which extensions are in use.") {
          it("Fails if clientExtensionResults is not a subset of the extensions requested by the Relying Party.") {
            val steps = finishRegistration(
              testData = RegistrationTestData.Packed.BasicAttestation.copy(
                requestedExtensions = Some(jsonFactory.objectNode()),
                clientExtensionResults = jsonFactory.objectNode().set("foo", jsonFactory.textNode("boo"))
              )
            )
            val step: steps.Step12 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

            step.validations shouldBe a [Failure[_]]
            step.validations.failed.get shouldBe an[AssertionError]
            step.next shouldBe a [Failure[_]]
          }

          it("Succeeds if clientExtensionResults is empty.") {
            val steps = finishRegistration(
              testData = RegistrationTestData.Packed.BasicAttestation.copy(
                requestedExtensions = None,
                clientExtensionResults = jsonFactory.objectNode()
              )
            )
            val step: steps.Step12 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

            step.validations shouldBe a [Success[_]]
            step.next shouldBe a [Success[_]]
          }

          it("Succeeds if clientExtensionResults is empty and requested extensions is an empty object.") {
            val steps = finishRegistration(
              testData = RegistrationTestData.Packed.BasicAttestation.copy(
                requestedExtensions = Some(jsonFactory.objectNode()),
                clientExtensionResults = jsonFactory.objectNode()
              )
            )
            val step: steps.Step12 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

            step.validations shouldBe a [Success[_]]
            step.next shouldBe a [Success[_]]
          }

          it("Succeeds if clientExtensionResults is a subset of the extensions requested by the Relying Party.") {
            val steps = finishRegistration(
              testData = RegistrationTestData.Packed.BasicAttestation.copy(
                requestedExtensions = Some(jsonFactory.objectNode().set("foo", jsonFactory.textNode("bar"))),
                clientExtensionResults = jsonFactory.objectNode().set("foo", jsonFactory.textNode("boo"))
              )
            )
            val step: steps.Step12 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

            step.validations shouldBe a [Success[_]]
            step.next shouldBe a [Success[_]]
          }
        }

        describe("authenticator extension outputs in the extensions in authData are as expected, considering the client extension input values that were given as the extensions option in the create() call. In particular, any extension identifier values in the extensions in authData MUST be also be present as extension identifier values in the extensions member of options, i.e., no extensions are present that were not requested. In the general case, the meaning of \"are as expected\" is specific to the Relying Party and which extensions are in use.") {
          it("Fails if authenticator extensions is not a subset of the extensions requested by the Relying Party.") {
            val steps = finishRegistration(
              testData = RegistrationTestData.Packed.BasicAttestation.copy(
                requestedExtensions = Some(jsonFactory.objectNode())
              ).editAuthenticatorData(
                authData => authData.updated(32, (authData(32) | 0x80).toByte) ++
                  WebAuthnCodecs.cbor.writeValueAsBytes(jsonFactory.objectNode().set("foo", jsonFactory.textNode("boo"))).toVector
              )
            )
            val step: steps.Step12 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

            step.validations shouldBe a [Failure[_]]
            step.validations.failed.get shouldBe an[AssertionError]
            step.next shouldBe a [Failure[_]]

          }

          it("Succeeds if authenticator extensions is not present.") {
            val steps = finishRegistration(
              testData = RegistrationTestData.Packed.BasicAttestation.copy(
                requestedExtensions = None
              ).editAuthenticatorData(
                authData => authData.updated(32, (authData(32) & 0x7f).toByte)
              )
            )
            val step: steps.Step12 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

            step.validations shouldBe a [Success[_]]
            step.next shouldBe a [Success[_]]
          }

          it("Succeeds if authenticator extensions is empty.") {
            val steps = finishRegistration(
              testData = RegistrationTestData.Packed.BasicAttestation.copy(
                requestedExtensions = None
              ).editAuthenticatorData(
                authData => authData.updated(32, (authData(32) | 0x80).toByte) ++
                  WebAuthnCodecs.cbor.writeValueAsBytes(jsonFactory.objectNode()).toVector
              )
            )
            val step: steps.Step12 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

            step.validations shouldBe a [Success[_]]
            step.next shouldBe a [Success[_]]
          }

          it("Succeeds if authenticator extensions is not present and requested extensions is an empty object.") {
            val steps = finishRegistration(
              testData = RegistrationTestData.Packed.BasicAttestation.copy(
                requestedExtensions = Some(jsonFactory.objectNode())
              ).editAuthenticatorData(
                authData => authData.updated(32, (authData(32) & 0x7f).toByte)
              )
            )
            val step: steps.Step12 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

            step.validations shouldBe a [Success[_]]
            step.next shouldBe a [Success[_]]
          }

          it("Succeeds if authenticator extensions is empty and requested extensions is an empty object.") {
            val steps = finishRegistration(
              testData = RegistrationTestData.Packed.BasicAttestation.copy(
                requestedExtensions = Some(jsonFactory.objectNode())
              ).editAuthenticatorData(
                authData => authData.updated(32, (authData(32) | 0x80).toByte) ++
                  WebAuthnCodecs.cbor.writeValueAsBytes(jsonFactory.objectNode()).toVector
              )
            )
            val step: steps.Step12 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

            step.validations shouldBe a [Success[_]]
            step.next shouldBe a [Success[_]]
          }

          it("Succeeds if authenticator extensions is a subset of the extensions requested by the Relying Party.") {
            val steps = finishRegistration(
              testData = RegistrationTestData.Packed.BasicAttestation.copy(
                requestedExtensions = Some(jsonFactory.objectNode().set("foo", jsonFactory.textNode("bar")))
              ).editAuthenticatorData(
                authData => authData.updated(32, (authData(32) | 0x80).toByte) ++
                  WebAuthnCodecs.cbor.writeValueAsBytes(jsonFactory.objectNode().set("foo", jsonFactory.textNode("boo"))).toVector
              )
            )
            val step: steps.Step12 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

            step.validations shouldBe a [Success[_]]
            step.next shouldBe a [Success[_]]
          }
        }

      }

      describe("13. Determine the attestation statement format by performing a USASCII case-sensitive match on fmt against the set of supported WebAuthn Attestation Statement Format Identifier values. The up-to-date list of registered WebAuthn Attestation Statement Format Identifier values is maintained in the in the IANA registry of the same name [WebAuthn-Registries].") {
        def setup(format: String): FinishRegistrationSteps = {
          finishRegistration(
            testData = RegistrationTestData.FidoU2f.BasicAttestation.editAttestationObject("fmt", format)
          )
        }

        def checkFailure(format: String): Unit = {
          it(s"""Fails if fmt is "${format}".""") {
            val steps = setup(format)
            val step: steps.Step13 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

            step.validations shouldBe a [Failure[_]]
            step.validations.failed.get shouldBe an [AssertionError]
            step.next shouldBe a [Failure[_]]
          }
        }

        def checkSuccess(format: String): Unit = {
          it(s"""Succeeds if fmt is "${format}".""") {
            val steps = setup(format)
            val step: steps.Step13 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

            step.validations shouldBe a [Success[_]]
            step.next shouldBe a [Success[_]]
            step.format should equal (format)
            step.formatSupported should be(true)
          }
        }

        ignore("Succeeds if fmt is android-key.") { checkSuccess("android-key") }
        ignore("Succeeds if fmt is android-safetynet.") { checkSuccess("android-safetynet") }
        checkSuccess("fido-u2f")
        checkSuccess("none")
        checkSuccess("packed")
        ignore("Succeeds if fmt is tpm.") { checkSuccess("tpm") }

        checkFailure("FIDO-U2F")
        checkFailure("Fido-U2F")
        checkFailure("bleurgh")
      }

      describe("14. Verify that attStmt is a correct attestation statement, conveying a valid attestation signature, by using the attestation statement format fmt’s verification procedure given attStmt, authData and the hash of the serialized client data computed in step 7.") {

        describe("For the fido-u2f statement format,") {
          it("the default test case is a valid basic attestation.") {
            val steps = finishRegistration(testData = RegistrationTestData.FidoU2f.BasicAttestation)
            val step: steps.Step14 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

            step.validations shouldBe a [Success[_]]
            step.attestationType should equal (Basic)
            step.next shouldBe a [Success[_]]
          }

          it("a test case with self attestation is valid.") {
            val steps = finishRegistration(testData = RegistrationTestData.FidoU2f.SelfAttestation)
            val step: steps.Step14 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

            step.validations shouldBe a [Success[_]]
            step.attestationType should equal (SelfAttestation)
            step.next shouldBe a [Success[_]]
          }

          def flipByte(index: Int, bytes: ArrayBuffer): ArrayBuffer = bytes.updated(index, (0xff ^ bytes(index)).toByte)

          it("a test case with different signed client data is not valid.") {
            val testData = RegistrationTestData.FidoU2f.SelfAttestation
            val steps = finishRegistration(testData = RegistrationTestData.FidoU2f.BasicAttestation)
            val step: steps.Step14 = new steps.Step14(
              attestation = AttestationObject(testData.attestationObject),
              clientDataJsonHash = new BouncyCastleCrypto().hash(testData.clientDataJsonBytes.updated(20, (testData.clientDataJsonBytes(20) + 1).toByte).toArray).toVector,
              attestationStatementVerifier = FidoU2fAttestationStatementVerifier,
              warnings = Nil
            )

            step.validations shouldBe a [Failure[_]]
            step.validations.failed.get shouldBe an [AssertionError]
            step.next shouldBe a [Failure[_]]
          }

          def checkByteFlipFails(index: Int): Unit = {
            val testData = RegistrationTestData.FidoU2f.BasicAttestation.editAuthenticatorData { flipByte(index, _) }

            val steps = finishRegistration(
              testData = testData,
              credentialId = Some(Vector.fill[Byte](16)(0))
            )
            val step: steps.Step14 = new steps.Step14(
              attestation = AttestationObject(testData.attestationObject),
              clientDataJsonHash = new BouncyCastleCrypto().hash(testData.clientDataJsonBytes.toArray).toVector,
              attestationStatementVerifier = FidoU2fAttestationStatementVerifier,
              warnings = Nil
            )

            step.validations shouldBe a [Failure[_]]
            step.validations.failed.get shouldBe an [AssertionError]
            step.next shouldBe a [Failure[_]]
          }

          it("a test case with a different signed RP ID hash is not valid.") {
            checkByteFlipFails(0)
          }

          it("a test case with a different signed credential ID is not valid.") {
            checkByteFlipFails(32 + 1 + 4 + 16 + 2 + 1)
          }

          it("a test case with a different signed credential public key is not valid.") {
            val testData = RegistrationTestData.FidoU2f.BasicAttestation.editAuthenticatorData { authenticatorData =>
              val decoded = AuthenticatorData(authenticatorData)
              val L = decoded.attestationData.get.credentialId.length
              val evilPublicKey = decoded.attestationData.get.credentialPublicKey.updated(30, 0: Byte)

              authenticatorData.take(32 + 1 + 4 + 16 + 2 + L) ++ evilPublicKey
            }
            val steps = finishRegistration(
              testData = testData,
              credentialId = Some(Vector.fill[Byte](16)(0))
            )
            val step: steps.Step14 = new steps.Step14(
              attestation = AttestationObject(testData.attestationObject),
              clientDataJsonHash = new BouncyCastleCrypto().hash(testData.clientDataJsonBytes.toArray).toVector,
              attestationStatementVerifier = FidoU2fAttestationStatementVerifier,
              warnings = Nil
            )

            step.validations shouldBe a [Failure[_]]
            step.validations.failed.get shouldBe an [AssertionError]
            step.next shouldBe a [Failure[_]]
          }

          describe("if x5c is not a certificate for an ECDSA public key over the P-256 curve, stop verification and return an error.") {
            val testAuthenticator = TestAuthenticator

            def checkRejected(keypair: KeyPair): Unit = {
              val (credential, _) = testAuthenticator.createBasicAttestedCredential(attestationCertAndKey = Some(testAuthenticator.generateAttestationCertificate(keypair)))

              val steps = finishRegistration(
                testData = RegistrationTestData(
                  attestationObject = credential.response.attestationObject,
                  clientDataJson = new String(credential.response.clientDataJSON.toArray, "UTF-8")
                ),
                credentialId = Some(credential.rawId)
              )
              val step: steps.Step14 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

              val standaloneVerification = Try {
                FidoU2fAttestationStatementVerifier.verifyAttestationSignature(
                  credential.response.attestation,
                  new BouncyCastleCrypto().hash(credential.response.clientDataJSON.toArray).toVector
                )
              }

              step.validations shouldBe a [Failure[_]]
              step.validations.failed.get shouldBe an [AssertionError]
              step.next shouldBe a [Failure[_]]

              standaloneVerification shouldBe a [Failure[_]]
              standaloneVerification.failed.get shouldBe an [AssertionError]
            }

            def checkAccepted(keypair: KeyPair): Unit = {
              val (credential, _) = testAuthenticator.createBasicAttestedCredential(attestationCertAndKey = Some(testAuthenticator.generateAttestationCertificate(keypair)))

              val steps = finishRegistration(
                testData = RegistrationTestData(
                  attestationObject = credential.response.attestationObject,
                  clientDataJson = new String(credential.response.clientDataJSON.toArray, "UTF-8")
                ),
                credentialId = Some(credential.rawId)
              )
              val step: steps.Step14 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

              val standaloneVerification = Try {
                FidoU2fAttestationStatementVerifier.verifyAttestationSignature(
                  credential.response.attestation,
                  new BouncyCastleCrypto().hash(credential.response.clientDataJSON.toArray).toVector
                )
              }

              step.validations shouldBe a [Success[_]]
              step.next shouldBe a [Success[_]]

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
          def flipByte(index: Int, bytes: ArrayBuffer): ArrayBuffer = bytes.updated(index, (0xff ^ bytes(index)).toByte)

          def checkByteFlipSucceeds(mutationDescription: String, index: Int): Unit = {
            it(s"the default test case with mutated ${mutationDescription} is accepted.") {
              val testData = RegistrationTestData.NoneAttestation.Default.editAuthenticatorData {
                flipByte(index, _)
              }

              val steps = finishRegistration(testData = testData)
              val step: steps.Step14 = new steps.Step14(
                attestation = AttestationObject(testData.attestationObject),
                clientDataJsonHash = new BouncyCastleCrypto().hash(testData.clientDataJsonBytes.toArray).toVector,
                attestationStatementVerifier = NoneAttestationStatementVerifier,
                warnings = Nil
              )

              step.validations shouldBe a [Success[_]]
              step.attestationType should equal (NoneAttestation)
              step.next shouldBe a [Success[_]]
            }
          }

          it("the default test case is accepted.") {
            val steps = finishRegistration(testData = RegistrationTestData.NoneAttestation.Default)
            val step: steps.Step14 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

            step.validations shouldBe a [Success[_]]
            step.attestationType should equal (NoneAttestation)
            step.next shouldBe a [Success[_]]
          }

          checkByteFlipSucceeds("signature counter", 32 + 1)
          checkByteFlipSucceeds("AAGUID", 32 + 1 + 4)
          checkByteFlipSucceeds("credential ID", 32 + 1 + 4 + 16 + 2)
        }

        describe("For the packed statement format") {
          val verifier = PackedAttestationStatementVerifier

          it("the attestation statement verifier implementation is PackedAttestationStatementVerifier.") {
            val steps = finishRegistration(testData = RegistrationTestData.Packed.BasicAttestation)
            val step: steps.Step14 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

            step.attestationStatementVerifier should be theSameInstanceAs PackedAttestationStatementVerifier
          }

          describe("the verification procedure is:") {
            describe("1. Verify that the given attestation statement is valid CBOR conforming to the syntax defined above.") {

              it("Fails if attStmt.sig is a text value.") {
                val testData = RegistrationTestData.Packed.BasicAttestation
                  .editAttestationObject("attStmt", jsonFactory.objectNode().set("sig", jsonFactory.textNode("foo")))

                val result: Try[Boolean] = verifier._verifyAttestationSignature(
                  AttestationObject(testData.attestationObject),
                  testData.clientDataJsonHash
                )

                result shouldBe a [Failure[_]]
                result.failed.get shouldBe an [AssertionError]
              }

              it("Fails if attStmt.sig is missing.") {
                val testData = RegistrationTestData.Packed.BasicAttestation
                  .editAttestationObject("attStmt", jsonFactory.objectNode().set("x5c", jsonFactory.arrayNode()))

                val result: Try[Boolean] = verifier._verifyAttestationSignature(
                  AttestationObject(testData.attestationObject),
                  testData.clientDataJsonHash
                )

                result shouldBe a [Failure[_]]
                result.failed.get shouldBe an [AssertionError]
              }
            }

            it("2. Let authenticatorData denote the authenticator data claimed to have been used for the attestation, and let clientDataHash denote the hash of the serialized client data.") {
              val testData = RegistrationTestData.Packed.BasicAttestation
              val authenticatorData: AuthenticatorData = AttestationObject(testData.attestationObject).authenticatorData
              val clientDataHash = MessageDigest.getInstance("SHA-256").digest(testData.clientDataJson.getBytes("UTF-8"))

              authenticatorData should not be null
              clientDataHash should not be null
            }

            describe("3. If x5c is present, this indicates that the attestation type is not ECDAA. In this case:") {
              it("The attestation type is identified as Basic.") {
                val steps = finishRegistration(testData = RegistrationTestData.Packed.BasicAttestation)
                val step: steps.Step14 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

                step.validations shouldBe a [Success[_]]
                step.next shouldBe a [Success[_]]
                step.attestationType should be (Basic)
              }

              describe("1. Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using the attestation public key in x5c with the algorithm specified in alg.") {
                it("Succeeds for the default test case.") {
                  val testData = RegistrationTestData.Packed.BasicAttestation
                  val result: Try[Boolean] = verifier._verifyAttestationSignature(
                    AttestationObject(testData.attestationObject),
                    testData.clientDataJsonHash
                  )
                  result should equal (Success(true))
                }

                it("Fail if the default test case is mutated.") {
                  val testData = RegistrationTestData.Packed.BasicAttestation

                  val result: Try[Boolean] = verifier._verifyAttestationSignature(
                    AttestationObject(testData.editAuthenticatorData({ authData: ArrayBuffer => authData.updated(16, if (authData(16) == 0) 1: Byte else 0: Byte) }).attestationObject),
                    testData.clientDataJsonHash
                  )
                  result should equal (Success(false))
                }
              }

              describe("2. Verify that x5c meets the requirements in §7.2.1 Packed attestation statement certificate requirements.") {
                it("Fails for an attestation signature with an invalid country code.") {
                  val authenticator = TestAuthenticator
                  val (badCert, key): (X509Certificate, PrivateKey) = authenticator.generateAttestationCertificate(
                    name = new X500Name("O=Yubico, C=AA, OU=Authenticator Attestation")
                  )
                  val (credential, _) = authenticator.createBasicAttestedCredential(
                    attestationCertAndKey = Some(badCert, key),
                    attestationStatementFormat = "packed"
                  )
                  val result = Try(verifier.verifyAttestationSignature(credential.response.attestation, sha256(credential.response.clientDataJSON)))

                  result shouldBe a [Failure[_]]
                  result.failed.get shouldBe an [AssertionError]
                }

                it("succeeds for the default test case.") {
                  val testData = RegistrationTestData.Packed.BasicAttestation
                  val result = verifier.verifyAttestationSignature(
                    AttestationObject(testData.attestationObject),
                    testData.clientDataJsonHash
                  )
                  result should equal (true)
                }
              }

              describe("3. If x5c contains an extension with OID 1 3 6 1 4 1 45724 1 1 4 (id-fido-gen-ce-aaguid) verify that the value of this extension matches the AAGUID in authenticatorData.") {
                it("Succeeds for the default test case.") {
                  val testData = RegistrationTestData.Packed.BasicAttestation
                  val result = verifier.verifyAttestationSignature(
                    AttestationObject(testData.attestationObject),
                    testData.clientDataJsonHash
                  )

                  testData.packedAttestationCert.getNonCriticalExtensionOIDs.asScala should equal (Set("1.3.6.1.4.1.45724.1.1.4"))
                  result should equal (true)
                }

                it("Succeeds if the attestation certificate does not have the extension.") {
                  val testData = RegistrationTestData.Packed.BasicAttestationWithoutAaguidExtension

                  val result = verifier.verifyAttestationSignature(
                    AttestationObject(testData.attestationObject),
                    testData.clientDataJsonHash
                  )

                  testData.packedAttestationCert.getNonCriticalExtensionOIDs shouldBe null
                  result should equal (true)
                }

                it("Fails if the attestation certificate has the extension and it does not match the AAGUID.") {
                  val testData = RegistrationTestData.Packed.BasicAttestationWithWrongAaguidExtension

                  val result = verifier._verifyAttestationSignature(
                    AttestationObject(testData.attestationObject),
                    testData.clientDataJsonHash
                  )

                  testData.packedAttestationCert.getNonCriticalExtensionOIDs should not be empty
                  result shouldBe a [Failure[_]]
                  result.failed.get shouldBe an [AssertionError]
                }
              }

              it("If successful, return attestation type Basic and trust path x5c.") {
                val testData = RegistrationTestData.Packed.BasicAttestation
                val steps = finishRegistration(testData = testData)
                val step: steps.Step14 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

                step.validations shouldBe a [Success[_]]
                step.next shouldBe a [Success[_]]
                step.attestationType should be (Basic)
                step.attestationTrustPath should not be empty
                step.attestationTrustPath.get should be (List(testData.packedAttestationCert))
              }
            }

            describe("4. If ecdaaKeyId is present, then the attestation type is ECDAA. In this case:") {
              ignore("1. Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using ECDAA-Verify with ECDAA-Issuer public key identified by ecdaaKeyId (see [FIDOEcdaaAlgorithm]).") {
                fail("Test not implemented.")
              }

              ignore("2. If successful, return attestation type ECDAA and trust path ecdaaKeyId.") {
                fail("Test not implemented.")
              }
            }

            describe("5. If neither x5c nor ecdaaKeyId is present, self attestation is in use.") {
              val testDataBase = RegistrationTestData.Packed.SelfAttestation

              it("The attestation type is identified as SelfAttestation.") {
                val steps = finishRegistration(testData = testDataBase)
                val step: steps.Step14 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

                step.validations shouldBe a [Success[_]]
                step.next shouldBe a [Success[_]]
                step.attestationType should be (SelfAttestation)
              }

              describe("1. Validate that alg matches the algorithm of the credential private key in authenticatorData.") {
                it("Succeeds for the default test case.") {
                  val result = verifier.verifyAttestationSignature(
                    AttestationObject(testDataBase.attestationObject),
                    testDataBase.clientDataJsonHash
                  )

                  CBORObject.DecodeFromBytes(AttestationObject(testDataBase.attestationObject).authenticatorData.attestationData.get.credentialPublicKey.toArray).get(CBORObject.FromObject(3)).AsInt64 should equal (-7)
                  AttestationObject(testDataBase.attestationObject).attestationStatement.get("alg").longValue should equal (-7)
                  result should equal (true)
                }

                it("Fails if the alg is a different value.") {
                  val testData = RegistrationTestData.Packed.SelfAttestationWithWrongAlgValue
                  val result = verifier._verifyAttestationSignature(
                    AttestationObject(testData.attestationObject),
                    testData.clientDataJsonHash
                  )

                  CBORObject.DecodeFromBytes(AttestationObject(testData.attestationObject).authenticatorData.attestationData.get.credentialPublicKey.toArray).get(CBORObject.FromObject(3)).AsInt64 should equal (-7)
                  AttestationObject(testData.attestationObject).attestationStatement.get("alg").longValue should equal (-8)
                  result shouldBe a [Failure[_]]
                  result.failed.get shouldBe an [AssertionError]
                }
              }

              describe("2. Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash using the credential public key with alg.") {
                it("Succeeds for the default test case.") {
                  val result = verifier.verifyAttestationSignature(
                    AttestationObject(testDataBase.attestationObject),
                    testDataBase.clientDataJsonHash
                  )
                  result should equal (true)
                }

                it("Fails if the attestation object is mutated.") {
                  val testData = testDataBase.editAuthenticatorData { authData: ArrayBuffer => authData.updated(16, if (authData(16) == 0) 1: Byte else 0: Byte) }
                  val result = verifier.verifyAttestationSignature(
                    AttestationObject(testData.attestationObject),
                    testData.clientDataJsonHash
                  )
                  result should equal (false)
                }

                it("Fails if the client data is mutated.") {
                  val result = verifier.verifyAttestationSignature(
                    AttestationObject(testDataBase.attestationObject),
                    sha256(testDataBase.clientDataJson.updated(4, 'ä').getBytes("UTF-8").toVector)
                  )
                  result should equal (false)
                }

                it("Fails if the client data hash is mutated.") {
                  val result = verifier.verifyAttestationSignature(
                    AttestationObject(testDataBase.attestationObject),
                    testDataBase.clientDataJsonHash.updated(7, if (testDataBase.clientDataJsonHash(7) == 0) 1: Byte else 0: Byte))
                  result should equal (false)
                }
              }

              it("3. If successful, return attestation type Self and empty trust path.") {
                val testData = RegistrationTestData.Packed.SelfAttestation
                val steps = finishRegistration(testData = testData)
                val step: steps.Step14 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

                step.validations shouldBe a [Success[_]]
                step.next shouldBe a [Success[_]]
                step.attestationType should be (SelfAttestation)
                step.attestationTrustPath shouldBe empty
              }
            }
          }

          describe("7.2.1. Packed attestation statement certificate requirements") {
            val testDataBase = RegistrationTestData.Packed.BasicAttestation

            describe("The attestation certificate MUST have the following fields/extensions:") {
              it("Version must be set to 3.") {
                val badCert = Mockito.mock(classOf[X509Certificate])
                val principal = new X500Principal("O=Yubico, C=SE, OU=Authenticator Attestation")
                Mockito.when(badCert.getVersion) thenReturn 2
                Mockito.when(badCert.getSubjectX500Principal) thenReturn principal
                Mockito.when(badCert.getBasicConstraints) thenReturn -1
                val result = verifier._verifyX5cRequirements(badCert, testDataBase.aaguid)

                result shouldBe a [Failure[_]]
                result.failed.get shouldBe an [AssertionError]

                verifier._verifyX5cRequirements(testDataBase.packedAttestationCert, testDataBase.aaguid) should equal (Success(true))
              }

              describe("Subject field MUST be set to:") {
                it("Subject-C: Country where the Authenticator vendor is incorporated") {
                  val badCert: X509Certificate = TestAuthenticator.generateAttestationCertificate(
                    name = new X500Name("O=Yubico, C=AA, OU=Authenticator Attestation")
                  )._1
                  val result = verifier._verifyX5cRequirements(badCert, testDataBase.aaguid)

                  result shouldBe a [Failure[_]]
                  result.failed.get shouldBe an [AssertionError]

                  verifier._verifyX5cRequirements(testDataBase.packedAttestationCert, testDataBase.aaguid) should equal (Success(true))
                }

                it("Subject-O: Legal name of the Authenticator vendor") {
                  val badCert: X509Certificate = TestAuthenticator.generateAttestationCertificate(
                    name = new X500Name("C=SE, OU=Authenticator Attestation")
                  )._1
                  val result = verifier._verifyX5cRequirements(badCert, testDataBase.aaguid)

                  result shouldBe a [Failure[_]]
                  result.failed.get shouldBe an [AssertionError]

                  verifier._verifyX5cRequirements(testDataBase.packedAttestationCert, testDataBase.aaguid) should equal(Success(true))
                }

                it("Subject-OU: Authenticator Attestation") {
                  val badCert: X509Certificate = TestAuthenticator.generateAttestationCertificate(
                    name = new X500Name("O=Yubico, C=SE, OU=Foo")
                  )._1
                  val result = verifier._verifyX5cRequirements(badCert, testDataBase.aaguid)

                  result shouldBe a [Failure[_]]
                  result.failed.get shouldBe an [AssertionError]

                  verifier._verifyX5cRequirements(testDataBase.packedAttestationCert, testDataBase.aaguid) should equal(Success(true))
                }

                it("Subject-CN: No stipulation.") {
                  // Nothing to test
                }
              }

              it("If the related attestation root certificate is used for multiple authenticator models, the Extension OID 1 3 6 1 4 1 45724 1 1 4 (id-fido-gen-ce-aaguid) MUST be present, containing the AAGUID as value.") {
                val idFidoGenCeAaguid = "1.3.6.1.4.1.45724.1.1.4"

                val badCert: X509Certificate = TestAuthenticator.generateAttestationCertificate(
                  name = new X500Name("O=Yubico, C=SE, OU=Authenticator Attestation"),
                  extensions = List((idFidoGenCeAaguid, false, Vector(0, 1, 2, 3)))
                )._1
                val result = verifier._verifyX5cRequirements(badCert, testDataBase.aaguid)

                result shouldBe a [Failure[_]]
                result.failed.get shouldBe an [AssertionError]

                val goodCert: X509Certificate = TestAuthenticator.generateAttestationCertificate(
                  name = new X500Name("O=Yubico, C=SE, OU=Authenticator Attestation"),
                  extensions = Nil
                )._1
                val goodResult = verifier._verifyX5cRequirements(badCert, testDataBase.aaguid)

                goodResult shouldBe a [Failure[_]]
                goodResult.failed.get shouldBe an [AssertionError]

                verifier._verifyX5cRequirements(testDataBase.packedAttestationCert, testDataBase.aaguid) should equal(Success(true))
              }

              it("The Basic Constraints extension MUST have the CA component set to false") {
                val result = verifier._verifyX5cRequirements(testDataBase.attestationCaCert.get, testDataBase.aaguid)

                result shouldBe a [Failure[_]]
                result.failed.get shouldBe an [AssertionError]

                verifier._verifyX5cRequirements(testDataBase.packedAttestationCert, testDataBase.aaguid) should equal (Success(true))
              }

              describe("An Authority Information Access (AIA) extension with entry id-ad-ocsp and a CRL Distribution Point extension [RFC5280] are both optional as the status of many attestation certificates is available through authenticator metadata services. See, for example, the FIDO Metadata Service [FIDOMetadataService].") {
                it("Nothing to test.") {}
              }
            }
          }
        }

        ignore("The tpm statement format is supported.") {
          val steps = finishRegistration(testData = RegistrationTestData.Tpm.PrivacyCa)
          val step: steps.Step14 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

          step.validations shouldBe a [Success[_]]
          step.next shouldBe a [Success[_]]
        }

        ignore("The android-key statement format is supported.") {
          val steps = finishRegistration(testData = RegistrationTestData.AndroidKey.BasicAttestation)
          val step: steps.Step14 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

          step.validations shouldBe a [Success[_]]
          step.next shouldBe a [Success[_]]
        }

        ignore("The android-safetynet statement format is supported.") {
          val steps = finishRegistration(testData = RegistrationTestData.AndroidSafetynet.BasicAttestation)
          val step: steps.Step14 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

          step.validations shouldBe a [Success[_]]
          step.next shouldBe a [Success[_]]
        }
      }

      describe("15. If validation is successful, obtain a list of acceptable trust anchors (attestation root certificates or ECDAA-Issuer public keys) for that attestation type and attestation statement format fmt, from a trusted source or from policy. For example, the FIDO Metadata Service [FIDOMetadataService] provides one way to obtain such information, using the aaguid in the attestedCredentialData in authData.") {

        describe("For the fido-u2f statement format") {

          it("with self attestation, no trust anchors are returned.") {
            val steps = finishRegistration(testData = RegistrationTestData.FidoU2f.SelfAttestation)
            val step: steps.Step15 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

            step.validations shouldBe a [Success[_]]
            step.trustResolver.asScala shouldBe empty
            step.next shouldBe a [Success[_]]
          }

          it("with basic attestation, a trust resolver is returned.") {
            val metadataResolver: MetadataResolver = new SimpleResolver
            val metadataService: MetadataService = new MetadataService(metadataResolver, null, null)
            val steps = finishRegistration(
              testData = RegistrationTestData.FidoU2f.BasicAttestation,
              metadataService = Some(metadataService)
            )
            val step: steps.Step15 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

            step.validations shouldBe a [Success[_]]
            step.trustResolver.get should not be null
            step.next shouldBe a [Success[_]]
          }

        }

        describe("For the none statement format") {
          it("no trust anchors are returned.") {
            val steps = finishRegistration(testData = RegistrationTestData.NoneAttestation.Default)
            val step: steps.Step15 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

            step.validations shouldBe a [Success[_]]
            step.trustResolver.asScala shouldBe empty
            step.next shouldBe a [Success[_]]
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
              val step: steps.Step16 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

              step.validations shouldBe a [Failure[_]]
              step.validations.failed.get shouldBe an [AssertionError]
              step.attestationTrusted should be (false)
              step.next shouldBe a [Failure[_]]
            }

            it("is accepted if untrusted attestation is allowed.") {
              val steps = finishRegistration(
                testData = RegistrationTestData.NoneAttestation.Default,
                allowUntrustedAttestation = true
              )
              val step: steps.Step16 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

              step.validations shouldBe a [Success[_]]
              step.attestationTrusted should be (true)
              step.next shouldBe a [Success[_]]
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
              val step: steps.Step16 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

              step.validations shouldBe a [Failure[_]]
              step.validations.failed.get shouldBe an [AssertionError]
              step.attestationTrusted should be (false)
              step.next shouldBe a [Failure[_]]
            }

            it("is accepted if untrusted attestation is allowed.") {
              val steps = finishRegistration(
                testData = RegistrationTestData.FidoU2f.SelfAttestation,
                allowUntrustedAttestation = true
              )
              val step: steps.Step16 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

              step.validations shouldBe a [Success[_]]
              step.attestationTrusted should be (true)
              step.next shouldBe a [Success[_]]
            }
          }
        }

        ignore("If ECDAA was used, verify that the identifier of the ECDAA-Issuer public key used is included in the set of acceptable trust anchors obtained in step 15.") {
          fail("Not implemented.")
        }

        describe("Otherwise, use the X.509 certificates returned by the verification procedure to verify that the attestation public key correctly chains up to an acceptable root certificate.") {

          def generateTests(testData: RegistrationTestData): Unit = {
            it("is rejected if untrusted attestation is not allowed and trust cannot be derived from the trust anchors.") {
              val metadataResolver = new SimpleResolver
              val metadataService: MetadataService = new MetadataService(metadataResolver, null, null) // Stateful - do not share between tests
              val steps = finishRegistration(
                allowUntrustedAttestation = false,
                testData = testData,
                metadataService = Some(metadataService)
              )
              val step: steps.Step16 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

              step.validations shouldBe a [Failure[_]]
              step.attestationTrusted should be (false)
              step.attestationMetadata.asScala should not be empty
              step.attestationMetadata.get.getMetadataIdentifier should be (null)
              step.next shouldBe a [Failure[_]]
            }

            it("is accepted if untrusted attestation is allowed and trust cannot be derived from the trust anchors.") {
              val metadataResolver = new SimpleResolver
              val metadataService: MetadataService = new MetadataService(metadataResolver, null, null) // Stateful - do not share between tests
              val steps = finishRegistration(
                allowUntrustedAttestation = true,
                testData = testData,
                metadataService = Some(metadataService)
              )
              val step: steps.Step16 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

              step.validations shouldBe a [Success[_]]
              step.attestationTrusted should be (false)
              step.attestationMetadata.asScala should not be empty
              step.attestationMetadata.get.getMetadataIdentifier should be (null)
              step.next shouldBe a [Success[_]]
            }

            it("is accepted if trust can be derived from the trust anchors.") {
              val metadataResolver = new SimpleResolver
              val metadataService: MetadataService = new MetadataService(metadataResolver, null, null) // Stateful - do not share between tests

              metadataResolver.addMetadata(
                new MetadataObject(
                  toJsonObject(Map(
                    "vendorInfo" -> jsonFactory.objectNode(),
                    "trustedCertificates" -> jsonFactory.arrayNode().add(jsonFactory.textNode(TestAuthenticator.toPem(testData.attestationCaCert.get))),
                    "devices" -> jsonFactory.arrayNode(),
                    "identifier" -> jsonFactory.textNode("Test attestation CA"),
                    "version" -> jsonFactory.numberNode(42)
                  ))
                )
              )

              val steps = finishRegistration(
                testData = testData,
                metadataService = Some(metadataService)
              )
              val step: steps.Step16 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

              step.validations shouldBe a [Success[_]]
              step.attestationTrusted should be (true)
              step.attestationMetadata.asScala should not be empty
              step.attestationMetadata.get.getMetadataIdentifier should equal ("Test attestation CA")
              step.next shouldBe a [Success[_]]
            }
          }

          describe("An android-key basic attestation") {
            ignore("fails for now.") {
              fail("Test not implemented.")
            }
          }

          describe("An android-safetynet basic attestation") {
            ignore("fails for now.") {
              fail("Test not implemented.")
            }
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
            override def lookup(id: Base64UrlString, uh: Base64UrlString) = Some(
              RegisteredCredential(
                credentialId = U2fB64Encoding.decode(id).toVector,
                signatureCount = 1337L,
                publicKey = testData.response.response.attestation.authenticatorData.attestationData.get.parsedCredentialPublicKey,
                userHandle = U2fB64Encoding.decode(uh).toVector
              )
            ).asJava

            override def lookupAll(id: Base64UrlString) = id match {
              case id if id == testData.response.response.attestation.authenticatorData.attestationData.get.credentialIdBase64 =>
                Set(
                  RegisteredCredential(
                    credentialId = U2fB64Encoding.decode(id).toVector,
                    signatureCount = 1337L,
                    publicKey = testData.response.response.attestation.authenticatorData.attestationData.get.parsedCredentialPublicKey,
                    userHandle = testData.request.user.id
                  )
                )
              case _ => Set.empty
            }
            override def getCredentialIdsForUsername(username: String): java.util.List[PublicKeyCredentialDescriptor] = ???
            override def getUserHandleForUsername(username: String): Optional[Base64UrlString] = ???
            override def getUsernameForUserHandle(userHandle: Base64UrlString): Optional[String] = ???
          }

          val steps = finishRegistration(
            allowUntrustedAttestation = true,
            testData = testData,
            credentialRepository = Some(credentialRepository)
          )
          val step: steps.Step17 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

          step.validations shouldBe a [Failure[_]]
          step.validations.failed.get shouldBe an [AssertionError]
          step.next shouldBe an [Failure[_]]
        }

        it("Registration proceeds if the given credential ID is not already registered.") {
          val credentialRepository = new CredentialRepository {
            override def lookup(id: Base64UrlString, uh: Base64UrlString) = None.asJava
            override def lookupAll(id: Base64UrlString) = Set.empty
            override def getCredentialIdsForUsername(username: String): java.util.List[PublicKeyCredentialDescriptor] = ???
            override def getUserHandleForUsername(username: String): Optional[Base64UrlString] = ???
            override def getUsernameForUserHandle(userHandle: Base64UrlString): Optional[String] = ???
          }

          val steps = finishRegistration(
            allowUntrustedAttestation = true,
            testData = testData,
            credentialRepository = Some(credentialRepository)
          )
          val step: steps.Step17 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

          step.validations shouldBe a [Success[_]]
          step.next shouldBe a [Success[_]]
        }
      }

      describe("18. If the attestation statement attStmt verified successfully and is found to be trustworthy, then register the new credential with the account that was denoted in the options.user passed to create(), by associating it with the credentialId and credentialPublicKey in the attestedCredentialData in authData, as appropriate for the Relying Party's system.") {
        it("Nothing to test.") {}
      }

      describe("19. If the attestation statement attStmt successfully verified but is not trustworthy per step 16 above, the Relying Party SHOULD fail the registration ceremony.") {
        it("Nothing to test.") {}

        describe("NOTE: However, if permitted by policy, the Relying Party MAY register the credential ID and credential public key but treat the credential as one with self attestation (see §6.3.3 Attestation Types). If doing so, the Relying Party is asserting there is no cryptographic proof that the public key credential has been generated by a particular authenticator model. See [FIDOSecRef] and [UAFProtocol] for a more detailed discussion.") {
          it("Nothing to test.") {}
        }
      }

      it("(Deleted) If verification of the attestation statement failed, the Relying Party MUST fail the registration ceremony.") {
        val steps = finishRegistration(testData = RegistrationTestData.FidoU2f.BasicAttestation.editClientData("foo", "bar"))
        val step14: steps.Step14 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get
        val step15: Try[steps.Step15] = Try(step14.next.get)

        step14.validations shouldBe a [Failure[_]]
        step14.next shouldBe a [Failure[_]]

        step15 shouldBe a [Failure[_]]
        step15.failed.get shouldBe an [AssertionError]

        steps.run shouldBe a [Failure[_]]
        steps.run.failed.get shouldBe an [AssertionError]
      }

    }

  }

}
