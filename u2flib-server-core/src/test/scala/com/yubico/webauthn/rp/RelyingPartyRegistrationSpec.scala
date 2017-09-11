package com.yubico.webauthn.rp

import java.security.MessageDigest
import java.security.KeyPair

import com.fasterxml.jackson.core.JsonParseException
import com.fasterxml.jackson.databind.node.JsonNodeFactory
import com.fasterxml.jackson.databind.node.ObjectNode
import com.yubico.scala.util.JavaConverters._
import com.yubico.u2f.crypto.BouncyCastleCrypto
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding
import com.yubico.webauthn.RelyingParty
import com.yubico.webauthn.FinishRegistrationSteps
import com.yubico.webauthn.FidoU2fAttestationStatementVerifier
import com.yubico.webauthn.SelfAttestation
import com.yubico.webauthn.data.ArrayBuffer
import com.yubico.webauthn.data.AuthenticationExtensions
import com.yubico.webauthn.data.MakePublicKeyCredentialOptions
import com.yubico.webauthn.data.PublicKeyCredentialParameters
import com.yubico.webauthn.data.PublicKey
import com.yubico.webauthn.data.RelyingPartyIdentity
import com.yubico.webauthn.data.UserIdentity
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria
import com.yubico.webauthn.data.AttestationObject
import com.yubico.webauthn.data.CollectedClientData
import com.yubico.webauthn.data.AuthenticatorData
import com.yubico.webauthn.data.impl.PublicKeyCredential
import com.yubico.webauthn.data.impl.AuthenticatorAttestationResponse
import com.yubico.webauthn.test.TestAuthenticator
import com.yubico.webauthn.util.BinaryUtil
import com.yubico.webauthn.util.WebAuthnCodecs
import org.junit.runner.RunWith
import org.scalatest.FunSpec
import org.scalatest.Matchers
import org.scalatest.junit.JUnitRunner

import scala.util.Failure
import scala.util.Success
import scala.util.Try


@RunWith(classOf[JUnitRunner])
class RelyingPartyRegistrationSpec extends FunSpec with Matchers {

  def jsonFactory: JsonNodeFactory = JsonNodeFactory.instance

  object Defaults {
    // These values were generated using TestAuthenticator.makeCredentialExample(TestAuthenticator.createCredential())
    val attestationObject: ArrayBuffer = BinaryUtil.fromHex("bf68617574684461746158ad49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97634100000539000102030405060708090a0b0c0d0e0f0020a72294c582329187c69277030278e8e72dfde6e1e1a1bba035adde89beb0ac94bf63616c676545533235366178582100ec668b91afff289c1e1afaa85604540b053a0271107fd2d6f4d255a40133848a6179582100e611aff8789f14b415ef89e50b3be3b04e304ecac414f45cb70d0a9510ee33d4ff63666d74686669646f2d7532666761747453746d74bf637835639f59013b308201373081dea00302010202020539300a06082a8648ce3d04030230253123302106035504030c1a59756269636f20576562417574686e20756e6974207465737473301e170d3138303930363137343230305a170d3138303930363137343230305a30253123302106035504030c1a59756269636f20576562417574686e20756e69742074657374733059301306072a8648ce3d020106082a8648ce3d03010703420004357e1a3a0505da66d4f5940416af66634df18b3c78753888a438fc09dd45b3de20240772ca1c2b96bc082fe8841d887e828b5bdd7cb3721c023d9a871321c361300a06082a8648ce3d0403020348003045022100b4f90fcc70ba481c93b64d3e6e5d8906832ac8c7bdd520ad68481c784d3573b802204eebe8ff9a97faa834db98906c3b68b1dca03dc090cc31c139b0d561c44b8900ff637369675847304502210092ce43c314b4f2b94d15c5239c7c14c19907780901f4ef91a5648e99eb450c3a02200a9643e78d63b07469bd5426978e38d8ada153ffd81d0de276473a7322e0bcbcffff").get
    val clientDataJson: String = """{"challenge":"AAEBAgMFCA0VIjdZEGl5Yls","origin":"localhost","hashAlgorithm":"SHA-256"}"""

    // These values are defined by the attestationObject and clientDataJson above
    val clientData = CollectedClientData(WebAuthnCodecs.json.readTree(clientDataJson))
    val clientDataJsonBytes: ArrayBuffer = clientDataJson.getBytes("UTF-8").toVector
    val challenge: ArrayBuffer = U2fB64Encoding.decode(clientData.challenge).toVector
    val requestedExtensions: Option[AuthenticationExtensions] = None
    val clientExtensionResults: AuthenticationExtensions = jsonFactory.objectNode()

    val rpId = RelyingPartyIdentity(name = "Test party", id = "localhost")
    val userId = UserIdentity(name = "test@test.org", displayName = "Test user", id = "test")

    val createCredentialOptions = MakePublicKeyCredentialOptions(
      rp = rpId,
      user = userId,
      challenge = challenge,
      pubKeyCredParams = List(PublicKeyCredentialParameters(alg = -7)),
    )

  }

  def finishRegistration(
    allowSelfAttestation: Boolean = false,
    attestationObject: ArrayBuffer = Defaults.attestationObject,
    authenticatorRequirements: Option[AuthenticatorSelectionCriteria] = None,
    callerTokenBindingId: Option[String] = None,
    challenge: ArrayBuffer = Defaults.challenge,
    clientDataJsonBytes: ArrayBuffer = Defaults.clientDataJsonBytes,
    clientExtensionResults: AuthenticationExtensions = Defaults.clientExtensionResults,
    credentialId: Option[ArrayBuffer] = None,
    origin: String = Defaults.rpId.id,
    requestedExtensions: Option[AuthenticationExtensions] = Defaults.requestedExtensions,
    rpId: RelyingPartyIdentity = Defaults.rpId,
    userId: UserIdentity = Defaults.userId,
  ): FinishRegistrationSteps = {

    val request = MakePublicKeyCredentialOptions(
      rp = rpId,
      user = userId,
      challenge = challenge,
      pubKeyCredParams = List(PublicKeyCredentialParameters(`type` = PublicKey, alg = -7L)),
      extensions = requestedExtensions.asJava,
    )

    val response = PublicKeyCredential(
      credentialId getOrElse AttestationObject(attestationObject).authenticatorData.attestationData.get.credentialId,
      AuthenticatorAttestationResponse(attestationObject, clientDataJsonBytes),
      clientExtensionResults,
    )

    new RelyingParty(
      allowSelfAttestation = allowSelfAttestation,
      authenticatorRequirements = authenticatorRequirements.asJava,
      challengeGenerator = null,
      origin = origin,
      preferredPubkeyParams = request.pubKeyCredParams,
      rp = rpId,
      credentialRepository = null,
    )._finishRegistration(request, response, callerTokenBindingId.asJava)
  }

  describe("§6.1. Registering a new credential") {

    describe("When registering a new credential, represented by a AuthenticatorAttestationResponse structure, as part of a registration ceremony, a Relying Party MUST proceed as follows:") {

      it("1. Perform JSON deserialization on the clientDataJSON field of the AuthenticatorAttestationResponse object to extract the client data C claimed as collected during the credential creation.") {
        val malformedClientData = Vector[Byte]('{'.toByte)
        val steps = finishRegistration(clientDataJsonBytes = malformedClientData)
        val step1: steps.Step1 = steps.begin

        step1.validations shouldBe a [Failure[_]]
        step1.validations.failed.get shouldBe a [JsonParseException]
        step1.next shouldBe a [Failure[_]]
      }

      it("2. Verify that the challenge in C matches the challenge that was sent to the authenticator in the create() call.") {
        val steps = finishRegistration(challenge = Vector.fill(16)(0: Byte))
        val step2: steps.Step2 = steps.begin.next.get

        step2.validations shouldBe a [Failure[_]]
        step2.validations.failed.get shouldBe an [AssertionError]
        step2.next shouldBe a [Failure[_]]
      }

      it("3. Verify that the origin in C matches the Relying Party's origin.") {
        val steps = finishRegistration(origin = "root.evil")
        val step3: steps.Step3 = steps.begin.next.get.next.get

        step3.validations shouldBe a [Failure[_]]
        step3.validations.failed.get shouldBe an [AssertionError]
        step3.next shouldBe a [Failure[_]]
      }

      describe("4. Verify that the tokenBindingId in C matches the Token Binding ID for the TLS connection over which the attestation was obtained.") {
        it("Verification succeeds if neither side specifies token binding ID.") {
          val steps = finishRegistration()
          val step4: steps.Step4 = steps.begin.next.get.next.get.next.get

          step4.validations shouldBe a [Success[_]]
          step4.next shouldBe a [Success[_]]
        }

        it("Verification succeeds if both sides specify the same token binding ID.") {
          val clientDataJsonBytes: ArrayBuffer = BinaryUtil.fromHex("7b226368616c6c656e6765223a224141454241674d4643413056496a645a45476c35596c73222c226f726967696e223a226c6f63616c686f7374222c2268617368416c676f726974686d223a225348412d323536222c22746f6b656e42696e64696e674964223a2259454c4c4f575355424d4152494e45227d").get

          val steps = finishRegistration(
            callerTokenBindingId = Some("YELLOWSUBMARINE"),
            clientDataJsonBytes = clientDataJsonBytes,
          )
          val step: steps.Step4 = steps.begin.next.get.next.get.next.get

          step.validations shouldBe a [Success[_]]
          step.next shouldBe a [Success[_]]
        }

        it("Verification fails if caller specifies token binding ID but attestation does not.") {
          val steps = finishRegistration(callerTokenBindingId = Some("YELLOWSUBMARINE"))
          val step4: steps.Step4 = steps.begin.next.get.next.get.next.get

          step4.validations shouldBe a [Failure[_]]
          step4.validations.failed.get shouldBe an [AssertionError]
          step4.next shouldBe a [Failure[_]]
        }

        it("Verification fails if attestation specifies token binding ID but caller does not.") {
          val attestationObjectBytes: ArrayBuffer = BinaryUtil.fromHex("bf68617574684461746158ab49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97634100000539000102030405060708090a0b0c0d0e0f002067d2e4a43d68158d5be9786d7a708c94782669deda891bda4a586c1331e1d7bebf63616c67654553323536617858201f228113a2cc82ad4633ff58dffe09c8d28177f11590b737d1a13f628db33721617958207721f99e5ff74631df92d1c3ebc758e821cd1c7b323946d97f4ff43083cf0b2fff63666d74686669646f2d7532666761747453746d74bf637835639f59013b308201373081dea00302010202020539300a06082a8648ce3d04030230253123302106035504030c1a59756269636f20576562417574686e20756e6974207465737473301e170d3138303930363137343230305a170d3138303930363137343230305a30253123302106035504030c1a59756269636f20576562417574686e20756e69742074657374733059301306072a8648ce3d020106082a8648ce3d0301070342000485a43c1f4e2e625cc3ce85f0a7b827b1358be9c1be9d45fba1632e5e7f4d1db5488bd7a6101ae16457cb12a3d3408b989993e017c027e1af43624bdec1402e6e300a06082a8648ce3d040302034800304502205298725d18bd9645a8118f42f4a9a9fa49396851305c1bff3da01f29fc704656022100d93a584a1273b695f0c7497bf6fcc1a9ecbe29376c00a4abb25ff7af48a92ccfff63736967584630440220188eb445f56aa23f3be2f7b327cca187a34fd300af3d3c985fda6a8829f770440220340f2029d42d48bc021341d7054ee708a5d9223580faac6530990de8a5775a53ffff").get
          val clientDataJsonBytes: ArrayBuffer = BinaryUtil.fromHex("7b226368616c6c656e6765223a224141454241674d4643413056496a645a45476c35596c73222c226f726967696e223a226c6f63616c686f7374222c2268617368416c676f726974686d223a225348412d323536222c22746f6b656e42696e64696e674964223a2259454c4c4f575355424d4152494e45227d").get

          val steps = finishRegistration(
            callerTokenBindingId = None,
            attestationObject = attestationObjectBytes,
            clientDataJsonBytes = clientDataJsonBytes,
          )
          val step4: steps.Step4 = steps.begin.next.get.next.get.next.get

          step4.validations shouldBe a [Failure[_]]
          step4.validations.failed.get shouldBe an [AssertionError]
          step4.next shouldBe a [Failure[_]]
        }

        it("Verification fails if attestation and caller specify different token binding IDs.") {
          val attestationObjectBytes: ArrayBuffer = BinaryUtil.fromHex("bf68617574684461746158ab49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97634100000539000102030405060708090a0b0c0d0e0f002067d2e4a43d68158d5be9786d7a708c94782669deda891bda4a586c1331e1d7bebf63616c67654553323536617858201f228113a2cc82ad4633ff58dffe09c8d28177f11590b737d1a13f628db33721617958207721f99e5ff74631df92d1c3ebc758e821cd1c7b323946d97f4ff43083cf0b2fff63666d74686669646f2d7532666761747453746d74bf637835639f59013b308201373081dea00302010202020539300a06082a8648ce3d04030230253123302106035504030c1a59756269636f20576562417574686e20756e6974207465737473301e170d3138303930363137343230305a170d3138303930363137343230305a30253123302106035504030c1a59756269636f20576562417574686e20756e69742074657374733059301306072a8648ce3d020106082a8648ce3d0301070342000485a43c1f4e2e625cc3ce85f0a7b827b1358be9c1be9d45fba1632e5e7f4d1db5488bd7a6101ae16457cb12a3d3408b989993e017c027e1af43624bdec1402e6e300a06082a8648ce3d040302034800304502205298725d18bd9645a8118f42f4a9a9fa49396851305c1bff3da01f29fc704656022100d93a584a1273b695f0c7497bf6fcc1a9ecbe29376c00a4abb25ff7af48a92ccfff63736967584630440220188eb445f56aa23f3be2f7b327cca187a34fd300af3d3c985fda6a8829f770440220340f2029d42d48bc021341d7054ee708a5d9223580faac6530990de8a5775a53ffff").get
          val clientDataJsonBytes: ArrayBuffer = BinaryUtil.fromHex("7b226368616c6c656e6765223a224141454241674d4643413056496a645a45476c35596c73222c226f726967696e223a226c6f63616c686f7374222c2268617368416c676f726974686d223a225348412d323536222c22746f6b656e42696e64696e674964223a2259454c4c4f575355424d4152494e45227d").get

          val steps = finishRegistration(
            callerTokenBindingId = Some("ORANGESUBMARINE"),
            attestationObject = attestationObjectBytes,
            clientDataJsonBytes = clientDataJsonBytes,
          )
          val step4: steps.Step4 = steps.begin.next.get.next.get.next.get

          step4.validations shouldBe a [Failure[_]]
          step4.validations.failed.get shouldBe an [AssertionError]
          step4.next shouldBe a [Failure[_]]
        }
      }

      describe("5. Verify that the") {
        it("clientExtensions in C is a subset of the extensions requested by the RP.") {
          val failSteps = finishRegistration(
            clientDataJsonBytes =
              WebAuthnCodecs.json.writeValueAsBytes(
                WebAuthnCodecs.json.readTree(Defaults.clientDataJson).asInstanceOf[ObjectNode]
                  .set("clientExtensions", jsonFactory.objectNode().set("foo", jsonFactory.textNode("boo")))
              ).toVector,
          )
          val failStep5: failSteps.Step5 = failSteps.begin.next.get.next.get.next.get.next.get

          failStep5.validations shouldBe a [Failure[_]]
          failStep5.validations.failed.get shouldBe an[AssertionError]
          failStep5.next shouldBe a [Failure[_]]

          val successSteps = finishRegistration(
            requestedExtensions = Some(jsonFactory.objectNode().set("foo", jsonFactory.textNode("bar"))),
            clientDataJsonBytes =
              WebAuthnCodecs.json.writeValueAsBytes(
                WebAuthnCodecs.json.readTree(Defaults.clientDataJson).asInstanceOf[ObjectNode]
                  .set("clientExtensions", jsonFactory.objectNode().set("foo", jsonFactory.textNode("boo")))
              ).toVector,
          )
          val successStep5: successSteps.Step5 = successSteps.begin.next.get.next.get.next.get.next.get

          successStep5.validations shouldBe a [Success[_]]
          successStep5.next shouldBe a [Success[_]]
        }

        it("authenticatorExtensions in C is also a subset of the extensions requested by the RP.") {
          val failSteps = finishRegistration(
            clientDataJsonBytes =
              WebAuthnCodecs.json.writeValueAsBytes(
                WebAuthnCodecs.json.readTree(Defaults.clientDataJson).asInstanceOf[ObjectNode]
                  .set("authenticatorExtensions", jsonFactory.objectNode().set("foo", jsonFactory.textNode("boo")))
              ).toVector,
          )
          val failStep5: failSteps.Step5 = failSteps.begin.next.get.next.get.next.get.next.get

          failStep5.validations shouldBe a [Failure[_]]
          failStep5.validations.failed.get shouldBe an[AssertionError]
          failStep5.next shouldBe a [Failure[_]]

          val successSteps = finishRegistration(
            requestedExtensions = Some(jsonFactory.objectNode().set("foo", jsonFactory.textNode("bar"))),
            clientDataJsonBytes =
              WebAuthnCodecs.json.writeValueAsBytes(
                WebAuthnCodecs.json.readTree(Defaults.clientDataJson).asInstanceOf[ObjectNode]
                  .set("authenticatorExtensions", jsonFactory.objectNode().set("foo", jsonFactory.textNode("boo")))
              ).toVector,
          )
          val successStep5: successSteps.Step5 = successSteps.begin.next.get.next.get.next.get.next.get

          successStep5.validations shouldBe a [Success[_]]
          successStep5.next shouldBe a [Success[_]]
        }
      }

      describe("6. Compute the hash of clientDataJSON using the algorithm identified by C.hashAlgorithm.") {
        it("SHA-256 is allowed.") {
          val steps = finishRegistration()
          val step6: steps.Step6 = steps.begin.next.get.next.get.next.get.next.get.next.get

          step6.validations shouldBe a [Success[_]]
          step6.next shouldBe a [Success[_]]
          step6.clientDataJsonHash should equal (MessageDigest.getInstance("SHA-256").digest(Defaults.clientDataJsonBytes.toArray).toVector)
        }

        def checkForbidden(algorithm: String): Unit = {
          it(s"${algorithm} is forbidden.") {
            val steps = finishRegistration(
              clientDataJsonBytes =
                WebAuthnCodecs.json.writeValueAsBytes(
                  WebAuthnCodecs.json.readTree(Defaults.clientDataJson).asInstanceOf[ObjectNode]
                    .set("hashAlgorithm", jsonFactory.textNode(algorithm))
                ).toVector,
            )
            val step6: steps.Step6 = steps.begin.next.get.next.get.next.get.next.get.next.get

            step6.validations shouldBe a [Failure[_]]
            step6.validations.failed.get shouldBe an [AssertionError]
            step6.next shouldBe a [Failure[_]]
          }
        }
        checkForbidden("MD5")
        checkForbidden("SHA1")
      }

      it("7. Perform CBOR decoding on the attestationObject field of the AuthenticatorAttestationResponse structure to obtain the attestation statement format fmt, the authenticator data authData, and the attestation statement attStmt.") {
        val steps = finishRegistration()
        val step7: steps.Step7 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get

        step7.validations shouldBe a [Success[_]]
        step7.next shouldBe a [Success[_]]
        step7.attestation.format should equal ("fido-u2f")
        step7.attestation.authenticatorData should not be null
        step7.attestation.attestationStatement should not be null
      }

      describe("8. Verify that the RP ID hash in authData is indeed the SHA-256 hash of the RP ID expected by the RP.") {
        it("Fails if RP ID is different.") {
          val steps = finishRegistration(rpId = Defaults.rpId.copy(id = "root.evil"))
          val step8: steps.Step8 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get

          step8.validations shouldBe a [Failure[_]]
          step8.validations.failed.get shouldBe an [AssertionError]
          step8.next shouldBe a [Failure[_]]
        }

        it("Succeeds if RP ID is the same.") {
          val steps = finishRegistration()
          val step8: steps.Step8 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get

          step8.validations shouldBe a [Success[_]]
          step8.next shouldBe a [Success[_]]
        }
      }

      describe("9. Determine the attestation statement format by performing an USASCII case-sensitive match on fmt against the set of supported WebAuthn Attestation Statement Format Identifier values. The up-to-date list of registered WebAuthn Attestation Statement Format Identifier values is maintained in the in the IANA registry of the same name [WebAuthn-Registries].") {
        def setup(format: String): FinishRegistrationSteps = {
          val attestationObject: ArrayBuffer = WebAuthnCodecs.cbor.writeValueAsBytes(
            WebAuthnCodecs.cbor.readTree(Defaults.attestationObject.toArray)
              .asInstanceOf[ObjectNode]
              .set("fmt", jsonFactory.textNode(format))
          ).toVector

          finishRegistration(attestationObject = attestationObject)
        }

        def checkFailure(format: String): Unit = {
          it(s"""Fails if fmt is "${format}".""") {
            val steps = setup(format)
            val step9: steps.Step9 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

            step9.validations shouldBe a [Failure[_]]
            step9.validations.failed.get shouldBe an [AssertionError]
            step9.next shouldBe a [Failure[_]]
          }
        }

        def checkSuccess(format: String): Unit = {
          it(s"""Succeeds if fmt is "${format}".""") {
            val steps = setup(format)
            val step9: steps.Step9 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

            step9.validations shouldBe a [Success[_]]
            step9.next shouldBe a [Success[_]]
            step9.format should equal (format)
            step9.formatSupported should be(true)
          }
        }

        checkSuccess("android-key")
        checkSuccess("android-safetynet")
        checkSuccess("fido-u2f")
        checkSuccess("packed")
        checkSuccess("tpm")

        checkFailure("FIDO-U2F")
        checkFailure("Fido-U2F")
        checkFailure("bleurgh")
      }

      describe("10. Verify that attStmt is a correct, validly-signed attestation statement, using the attestation statement format fmt’s verification procedure given authenticator data authData and the hash of the serialized client data computed in step 6.") {

        describe("For the fido-u2f statement format,") {
          it("the default test case is a valid self attestation.") {
            val steps = finishRegistration()
            val step10: steps.Step10 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

            step10.validations shouldBe a [Success[_]]
            step10.attestationType should equal (SelfAttestation)
            step10.next shouldBe a [Success[_]]
          }

          def flipByte(index: Int, bytes: ArrayBuffer): ArrayBuffer = bytes.updated(index, (0xff ^ bytes(index)).toByte)

          it("a test case with different signed client data is not valid.") {
            val steps = finishRegistration()
            val step10: steps.Step10 = new steps.Step10(
              attestation = AttestationObject(Defaults.attestationObject),
              clientDataJsonHash = new BouncyCastleCrypto().hash(Defaults.clientDataJsonBytes.updated(20, (Defaults.clientDataJsonBytes(20) + 1).toByte).toArray).toVector,
              attestationStatementVerifier = verifier,
            )

            step10.validations shouldBe a [Failure[_]]
            step10.validations.failed.get shouldBe an [AssertionError]
            step10.next shouldBe a [Failure[_]]
          }

          def mutateAuthenticatorData(attestationObject: ArrayBuffer)(mutator: ArrayBuffer => ArrayBuffer): ArrayBuffer = {
            val decodedCbor: ObjectNode = WebAuthnCodecs.cbor.readTree(attestationObject.toArray).asInstanceOf[ObjectNode]
            decodedCbor.set("authData", jsonFactory.binaryNode(mutator(decodedCbor.get("authData").binaryValue().toVector).toArray))

            WebAuthnCodecs.cbor.writeValueAsBytes(decodedCbor).toVector
          }

          def checkByteFlipFails(index: Int): Unit = {
            val attestationObject = mutateAuthenticatorData(Defaults.attestationObject) {
              flipByte(index, _)
            }
            val steps = finishRegistration(
              attestationObject = attestationObject,
              credentialId = Some(Vector.fill[Byte](16)(0))
            )
            val step10: steps.Step10 = new steps.Step10(
              attestation = AttestationObject(attestationObject),
              clientDataJsonHash = new BouncyCastleCrypto().hash(Defaults.clientDataJsonBytes.toArray).toVector,
              attestationStatementVerifier = FidoU2fAttestationStatementVerifier,
            )

            step10.validations shouldBe a [Failure[_]]
            step10.validations.failed.get shouldBe an [AssertionError]
            step10.next shouldBe a [Failure[_]]
          }

          it("a test case with a different signed RP ID hash is not valid.") {
            checkByteFlipFails(0)
          }

          it("a test case with a different signed credential ID is not valid.") {
            checkByteFlipFails(32 + 1 + 4 + 16 + 2 + 1)
          }

          it("a test case with a different signed credential public key is not valid.") {
            val attestationObject = mutateAuthenticatorData(Defaults.attestationObject) { authenticatorData =>
              val decoded = AuthenticatorData(authenticatorData)
              val L = decoded.attestationData.get.credentialId.length
              val evilPublicKey = decoded.attestationData.get.credentialPublicKey.asInstanceOf[ObjectNode]
                .set("x", jsonFactory.binaryNode(Array.fill[Byte](32)(0)))

              authenticatorData.take(32 + 1 + 4 + 16 + 2 + L) ++ WebAuthnCodecs.cbor.writeValueAsBytes(evilPublicKey)
            }
            val steps = finishRegistration(
              attestationObject = attestationObject,
              credentialId = Some(Vector.fill[Byte](16)(0))
            )
            val step10: steps.Step10 = new steps.Step10(
              attestation = AttestationObject(attestationObject),
              clientDataJsonHash = new BouncyCastleCrypto().hash(Defaults.clientDataJsonBytes.toArray).toVector,
              attestationStatementVerifier = FidoU2fAttestationStatementVerifier,
            )

            step10.validations shouldBe a [Failure[_]]
            step10.validations.failed.get shouldBe an [AssertionError]
            step10.next shouldBe a [Failure[_]]
          }

          describe("if x5c is not a certificate for an ECDSA public key over the P-256 curve, stop verification and return an error.") {
            val testAuthenticator = new TestAuthenticator()

            def checkRejected(keypair: KeyPair): Unit = {
              val credential = testAuthenticator.createCredential(attestationCertAndKey = Some(testAuthenticator.generateAttestationCertificate(keypair)))

              val steps = finishRegistration(
                attestationObject = credential.response.attestationObject,
                credentialId = Some(credential.rawId),
                clientDataJsonBytes = credential.response.clientDataJSON,
              )
              val step10: steps.Step10 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

              val standaloneVerification = Try {
                FidoU2fAttestationStatementVerifier.verifyAttestationSignature(
                  credential.response.attestation,
                  new BouncyCastleCrypto().hash(credential.response.clientDataJSON.toArray).toVector,
                )
              }

              step10.validations shouldBe a [Failure[_]]
              step10.validations.failed.get shouldBe an [AssertionError]
              step10.next shouldBe a [Failure[_]]

              standaloneVerification shouldBe a [Failure[_]]
              standaloneVerification.failed.get shouldBe an [AssertionError]
            }

            def checkAccepted(keypair: KeyPair): Unit = {
              val credential = testAuthenticator.createCredential(attestationCertAndKey = Some(testAuthenticator.generateAttestationCertificate(keypair)))

              val steps = finishRegistration(
                attestationObject = credential.response.attestationObject,
                credentialId = Some(credential.rawId),
                clientDataJsonBytes = credential.response.clientDataJSON,
              )
              val step10: steps.Step10 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

              val standaloneVerification = Try {
                FidoU2fAttestationStatementVerifier.verifyAttestationSignature(
                  credential.response.attestation,
                  new BouncyCastleCrypto().hash(credential.response.clientDataJSON.toArray).toVector,
                )
              }

              step10.validations shouldBe a [Success[_]]
              step10.next shouldBe a [Success[_]]

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

        it("The packed statement format is supported.") {
          val attestationObject: ArrayBuffer = WebAuthnCodecs.cbor.writeValueAsBytes(
            WebAuthnCodecs.cbor.readTree(Defaults.attestationObject.toArray).asInstanceOf[ObjectNode]
              .set("fmt", jsonFactory.textNode("packed"))
          ).toVector
          val steps = finishRegistration(
            attestationObject = attestationObject,
          )
          val step10: steps.Step10 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

          step10.validations shouldBe a [Success[_]]
          step10.next shouldBe a [Success[_]]
        }

        it("The tpm statement format is supported.") {
          val attestationObject: ArrayBuffer = WebAuthnCodecs.cbor.writeValueAsBytes(
            WebAuthnCodecs.cbor.readTree(Defaults.attestationObject.toArray).asInstanceOf[ObjectNode]
              .set("fmt", jsonFactory.textNode("tpm"))
          ).toVector
          val steps = finishRegistration(
            attestationObject = attestationObject,
          )
          val step10: steps.Step10 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

          step10.validations shouldBe a [Success[_]]
          step10.next shouldBe a [Success[_]]
        }

        it("The android-key statement format is supported.") {
          val attestationObject: ArrayBuffer = WebAuthnCodecs.cbor.writeValueAsBytes(
            WebAuthnCodecs.cbor.readTree(Defaults.attestationObject.toArray).asInstanceOf[ObjectNode]
              .set("fmt", jsonFactory.textNode("android-key"))
          ).toVector
          val steps = finishRegistration(
            attestationObject = attestationObject,
          )
          val step10: steps.Step10 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

          step10.validations shouldBe a [Success[_]]
          step10.next shouldBe a [Success[_]]
        }

        it("The android-safetynet statement format is supported.") {
          val attestationObject: ArrayBuffer = WebAuthnCodecs.cbor.writeValueAsBytes(
            WebAuthnCodecs.cbor.readTree(Defaults.attestationObject.toArray).asInstanceOf[ObjectNode]
              .set("fmt", jsonFactory.textNode("android-safetynet"))
          ).toVector
          val steps = finishRegistration(
            attestationObject = attestationObject,
          )
          val step10: steps.Step10 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get

          step10.validations shouldBe a [Success[_]]
          step10.next shouldBe a [Success[_]]
        }
      }

      it("11. If validation is successful, obtain a list of acceptable trust anchors (attestation root certificates or ECDAA-Issuer public keys) for that attestation type and attestation statement format fmt, from a trusted source or from policy. For example, the FIDO Metadata Service [FIDOMetadataService] provides one way to obtain such information, using the AAGUID in the attestation data contained in authData.") {
        fail("Not implemented.")
      }

      describe("12. Assess the attestation trustworthiness using the outputs of the verification procedure in step 10, as follows:") {

        it("If self attestation was used, check if self attestation is acceptable under Relying Party policy.") {
          fail("Not implemented.")
        }

        it("If ECDAA was used, verify that the identifier of the ECDAA-Issuer public key used is included in the set of acceptable trust anchors obtained in step 11.") {
          fail("Not implemented.")
        }

        it("Otherwise, use the X.509 certificates returned by the verification procedure to verify that the attestation public key correctly chains up to an acceptable root certificate.") {
          fail("Not implemented.")
        }

      }

      it("13. If the attestation statement attStmt verified successfully and is found to be trustworthy, then register the new credential with the account that was denoted in the options.user passed to create(), by associating it with the credential ID and credential public key contained in authData’s attestation data, as appropriate for the Relying Party's systems.") {
        // Nothing to test
      }

      it("14. If the attestation statement attStmt successfully verified but is not trustworthy per step 12 above, the Relying Party SHOULD fail the registration ceremony.") {
        // Nothing to test
      }

      it("14. NOTE: However, if permitted by policy, the Relying Party MAY register the credential ID and credential public key but treat the credential as one with self attestation (see §5.3.3 Attestation Types). If doing so, the Relying Party is asserting there is no cryptographic proof that the public key credential has been generated by a particular authenticator model. See [FIDOSecRef] and [UAFProtocol] for a more detailed discussion.") {
        // Nothing to test
      }

      it("15. If verification of the attestation statement failed, the Relying Party MUST fail the registration ceremony.") {
        val steps = finishRegistration(
          clientDataJsonBytes = WebAuthnCodecs.json.writeValueAsBytes(
            WebAuthnCodecs.json.readTree(Defaults.clientDataJson.getBytes("UTF-8")).asInstanceOf[ObjectNode]
              .set("foo", jsonFactory.textNode("bar"))
          ).toVector
        )
        val step9: steps.Step9 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get.next.get
        val step10: steps.Step10 = step9.next.get

        step9.validations shouldBe a [Success[_]]
        step9.next shouldBe a [Success[_]]

        step10.validations shouldBe a [Failure[_]]
        step10.validations.failed.get shouldBe an [AssertionError]
        step10.next shouldBe a [Failure[_]]

        steps.run shouldBe a [Failure[_]]
        steps.run.failed.get shouldBe an [AssertionError]
      }

    }

  }

}
