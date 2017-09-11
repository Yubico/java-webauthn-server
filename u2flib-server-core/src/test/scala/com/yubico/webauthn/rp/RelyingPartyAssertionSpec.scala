package com.yubico.webauthn.rp

import java.security.MessageDigest
import java.security.KeyPair
import java.security.PublicKey
import java.util.Optional

import com.fasterxml.jackson.core.JsonParseException
import com.fasterxml.jackson.databind.node.JsonNodeFactory
import com.fasterxml.jackson.databind.node.ObjectNode
import com.yubico.scala.util.JavaConverters._
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding
import com.yubico.webauthn.RelyingParty
import com.yubico.webauthn.PublicKeyCredentialRequestOptions
import com.yubico.webauthn.FinishAssertionSteps
import com.yubico.webauthn.CredentialRepository
import com.yubico.webauthn.data.ArrayBuffer
import com.yubico.webauthn.data.AuthenticationExtensions
import com.yubico.webauthn.data.CollectedClientData
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor
import com.yubico.webauthn.data.RelyingPartyIdentity
import com.yubico.webauthn.data.Base64UrlString
import com.yubico.webauthn.data.impl.PublicKeyCredential
import com.yubico.webauthn.data.impl.AuthenticatorAssertionResponse
import com.yubico.webauthn.test.TestAuthenticator
import com.yubico.webauthn.util.BinaryUtil
import com.yubico.webauthn.util.WebAuthnCodecs
import org.junit.runner.RunWith
import org.scalatest.FunSpec
import org.scalatest.Matchers
import org.scalatest.junit.JUnitRunner

import scala.util.Failure
import scala.util.Success


@RunWith(classOf[JUnitRunner])
class RelyingPartyAssertionSpec extends FunSpec with Matchers {

  def jsonFactory: JsonNodeFactory = JsonNodeFactory.instance

  object Defaults {

    val rpId = RelyingPartyIdentity(name = "Test party", id = "localhost")

    // These values were generated using TestAuthenticator.makeCredentialExample(TestAuthenticator.createCredential())
    val authenticatorData: ArrayBuffer = BinaryUtil.fromHex("49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630100000539").get
    val clientDataJson: String = """{"challenge":"AAEBAgMFCA0VIjdZEGl5Yls","origin":"localhost","hashAlgorithm":"SHA-256"}"""
    val credentialId: ArrayBuffer = BinaryUtil.fromHex("").get
    val credentialKey: KeyPair = new TestAuthenticator().importEcKeypair(
      privateBytes = BinaryUtil.fromHex("308193020100301306072a8648ce3d020106082a8648ce3d030107047930770201010420dd17580fe3c2e374c79fb30fbef657e326119d18ae538160c831851b92df19d7a00a06082a8648ce3d030107a144034200049613906235a63e87c085d52901bde35dcd9ca424526a4de551abe7ef4e3157aee6d01e1f4f805ee323ebf5ee7a54d4008d6bb97d9281a97f83e0be31dc3b8ef6").get,
      publicBytes = BinaryUtil.fromHex("3059301306072a8648ce3d020106082a8648ce3d030107034200049613906235a63e87c085d52901bde35dcd9ca424526a4de551abe7ef4e3157aee6d01e1f4f805ee323ebf5ee7a54d4008d6bb97d9281a97f83e0be31dc3b8ef6").get,
    )
    val signature: ArrayBuffer = BinaryUtil.fromHex("3046022100e6f0c87a54aa16f2e0862035746f2732f3a8b27a404a29681f77d4a5c023861702210093b8b8da66ebce71c5bc467b61bc18277606ab895d25c226b066d5054345749a").get

    // These values are defined by the attestationObject and clientDataJson above
    val clientData = CollectedClientData(WebAuthnCodecs.json.readTree(clientDataJson))
    val clientDataJsonBytes: ArrayBuffer = clientDataJson.getBytes("UTF-8").toVector
    val challenge: ArrayBuffer = U2fB64Encoding.decode(clientData.challenge).toVector
    val requestedExtensions: Option[AuthenticationExtensions] = None
    val clientExtensionResults: AuthenticationExtensions = jsonFactory.objectNode()

  }

  def finishAssertion(
    allowCredentials: Option[Seq[PublicKeyCredentialDescriptor]] = Some(List(PublicKeyCredentialDescriptor(id = Defaults.credentialId))),
    authenticatorData: ArrayBuffer = Defaults.authenticatorData,
    callerTokenBindingId: Option[String] = None,
    challenge: ArrayBuffer = Defaults.challenge,
    clientDataJsonBytes: ArrayBuffer = Defaults.clientDataJsonBytes,
    clientExtensionResults: AuthenticationExtensions = Defaults.clientExtensionResults,
    credentialId: ArrayBuffer = Defaults.credentialId,
    credentialKey: KeyPair = Defaults.credentialKey,
    credentialRepository: Option[CredentialRepository] = None,
    origin: String = Defaults.rpId.id,
    requestedExtensions: Option[AuthenticationExtensions] = Defaults.requestedExtensions,
    rpId: RelyingPartyIdentity = Defaults.rpId,
    signature: ArrayBuffer = Defaults.signature,
  ): FinishAssertionSteps = {

    val request = PublicKeyCredentialRequestOptions(
      rpId = Some(rpId.id).asJava,
      challenge = challenge,
      allowCredentials = Some(List(PublicKeyCredentialDescriptor(id = credentialId))).asJava,
    )

    val response = PublicKeyCredential(
      credentialId,
      AuthenticatorAssertionResponse(
        clientDataJSON = clientDataJsonBytes,
        authenticatorData = authenticatorData,
        signature = signature,
      ),
      clientExtensionResults,
    )

    new RelyingParty(
      allowSelfAttestation = false,
      authenticatorRequirements = None.asJava,
      challengeGenerator = null,
      origin = origin,
      preferredPubkeyParams = Nil,
      rp = rpId,
      credentialRepository = credentialRepository getOrElse (
        (credId: Base64UrlString) => (if (credId == U2fB64Encoding.encode(credentialId.toArray)) Some(credentialKey.getPublic) else None).asJava
      ),
    )._finishAssertion(request, response, callerTokenBindingId.asJava)
  }

  describe("6.2. Verifying an authentication assertion") {

    describe("When verifying a given PublicKeyCredential structure (credential) as part of an authentication ceremony, the Relying Party MUST proceed as follows:") {

      describe("1. Using credential’s id attribute (or the corresponding rawId, if base64url encoding is inappropriate for your use case), look up the corresponding credential public key.") {
        it("Fails if the credential ID is unknown.") {
          val steps = finishAssertion(credentialRepository = Some((_) => None.asJava))
          val step1: steps.Step1 = steps.begin

          step1.validations shouldBe a [Failure[_]]
          step1.validations.failed.get shouldBe an [AssertionError]
          step1.next shouldBe a [Failure[_]]
        }

        it("Succeeds if the credential ID is known.") {
          val steps = finishAssertion(credentialRepository = Some((_) => Some(Defaults.credentialKey.getPublic).asJava))
          val step1: steps.Step1 = steps.begin

          step1.validations shouldBe a [Success[_]]
          step1.pubkey should equal (Defaults.credentialKey.getPublic)
          step1.next shouldBe a [Success[_]]
        }
      }

      describe("2. Let cData, aData and sig denote the value of credential’s response's clientDataJSON, authenticatorData, and signature respectively.") {
        it("Succeeds if all three are present.") {
          val steps = finishAssertion()
          val step2: steps.Step2 = steps.begin.next.get

          step2.validations shouldBe a [Success[_]]
          step2.clientData should not be null
          step2.authenticatorData should not be null
          step2.signature should not be null
          step2.next shouldBe a [Success[_]]
        }

        it("Fails if clientDataJSON is missing.") {
          val steps = finishAssertion(clientDataJsonBytes = null)
          val step2: steps.Step2 = steps.begin.next.get

          step2.validations shouldBe a [Failure[_]]
          step2.validations.failed.get shouldBe an [AssertionError]
          step2.next shouldBe a [Failure[_]]
        }

        it("Fails if authenticatorData is missing.") {
          val steps = finishAssertion(authenticatorData = null)
          val step2: steps.Step2 = steps.begin.next.get

          step2.validations shouldBe a [Failure[_]]
          step2.validations.failed.get shouldBe an [AssertionError]
          step2.next shouldBe a [Failure[_]]
        }

        it("Fails if signature is missing.") {
          val steps = finishAssertion(signature = null)
          val step2: steps.Step2 = steps.begin.next.get

          step2.validations shouldBe a [Failure[_]]
          step2.validations.failed.get shouldBe an [AssertionError]
          step2.next shouldBe a [Failure[_]]
        }
      }

      describe("3. Perform JSON deserialization on cData to extract the client data C used for the signature.") {
        it("Fails if cData is not valid JSON.") {
          val malformedClientData = Vector[Byte]('{'.toByte)
          val steps = finishAssertion(clientDataJsonBytes = malformedClientData)
          val step3: steps.Step3 = steps.begin.next.get.next.get

          step3.validations shouldBe a [Failure[_]]
          step3.validations.failed.get shouldBe a [JsonParseException]
          step3.next shouldBe a [Failure[_]]
        }

        it("Succeeds if cData is valid JSON.") {
          val malformedClientData = "{}".getBytes("UTF-8").toVector
          val steps = finishAssertion(clientDataJsonBytes = malformedClientData)
          val step3: steps.Step3 = steps.begin.next.get.next.get

          step3.validations shouldBe a [Success[_]]
          step3.clientData should not be null
          step3.next shouldBe a [Success[_]]
        }
      }

      it("4. Verify that the challenge member of C matches the challenge that was sent to the authenticator in the PublicKeyCredentialRequestOptions passed to the get() call.") {
        val steps = finishAssertion(challenge = Vector.fill(16)(0: Byte))
        val step2: steps.Step2 = steps.begin.next.get

        step2.validations shouldBe a [Failure[_]]
        step2.validations.failed.get shouldBe an [AssertionError]
        step2.next shouldBe a [Failure[_]]
      }

      it("5. Verify that the origin member of C matches the Relying Party's origin.") {
        val steps = finishAssertion(origin = "root.evil")
        val step3: steps.Step3 = steps.begin.next.get.next.get

        step3.validations shouldBe a [Failure[_]]
        step3.validations.failed.get shouldBe an [AssertionError]
        step3.next shouldBe a [Failure[_]]
      }

      describe("6. Verify that the tokenBindingId member of C (if present) matches the Token Binding ID for the TLS connection over which the signature was obtained.") {
        it("Verification succeeds if neither side specifies token binding ID.") {
          val steps = finishAssertion()
          val step4: steps.Step4 = steps.begin.next.get.next.get.next.get

          step4.validations shouldBe a [Success[_]]
          step4.next shouldBe a [Success[_]]
        }

        it("Verification fails if caller specifies token binding ID but attestation does not.") {
          val steps = finishAssertion(callerTokenBindingId = Some("YELLOWSUBMARINE"))
          val step4: steps.Step4 = steps.begin.next.get.next.get.next.get

          step4.validations shouldBe a [Failure[_]]
          step4.validations.failed.get shouldBe an [AssertionError]
          step4.next shouldBe a [Failure[_]]
        }

        it("Verification fails if attestation specifies token binding ID but caller does not.") {
          val attestationObjectBytes: ArrayBuffer = BinaryUtil.fromHex("bf68617574684461746158ab49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97634100000539000102030405060708090a0b0c0d0e0f002067d2e4a43d68158d5be9786d7a708c94782669deda891bda4a586c1331e1d7bebf63616c67654553323536617858201f228113a2cc82ad4633ff58dffe09c8d28177f11590b737d1a13f628db33721617958207721f99e5ff74631df92d1c3ebc758e821cd1c7b323946d97f4ff43083cf0b2fff63666d74686669646f2d7532666761747453746d74bf637835639f59013b308201373081dea00302010202020539300a06082a8648ce3d04030230253123302106035504030c1a59756269636f20576562417574686e20756e6974207465737473301e170d3138303930363137343230305a170d3138303930363137343230305a30253123302106035504030c1a59756269636f20576562417574686e20756e69742074657374733059301306072a8648ce3d020106082a8648ce3d0301070342000485a43c1f4e2e625cc3ce85f0a7b827b1358be9c1be9d45fba1632e5e7f4d1db5488bd7a6101ae16457cb12a3d3408b989993e017c027e1af43624bdec1402e6e300a06082a8648ce3d040302034800304502205298725d18bd9645a8118f42f4a9a9fa49396851305c1bff3da01f29fc704656022100d93a584a1273b695f0c7497bf6fcc1a9ecbe29376c00a4abb25ff7af48a92ccfff63736967584630440220188eb445f56aa23f3be2f7b327cca187a34fd300af3d3c985fda6a8829f770440220340f2029d42d48bc021341d7054ee708a5d9223580faac6530990de8a5775a53ffff").get
          val clientDataJsonBytes: ArrayBuffer = BinaryUtil.fromHex("7b226368616c6c656e6765223a224141454241674d4643413056496a645a45476c35596c73222c226f726967696e223a226c6f63616c686f7374222c2268617368416c676f726974686d223a225348412d323536222c22746f6b656e42696e64696e674964223a2259454c4c4f575355424d4152494e45227d").get

          val steps = finishAssertion(
            callerTokenBindingId = None,
            authenticatorData = ???,
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

          val steps = finishAssertion(
            callerTokenBindingId = Some("ORANGESUBMARINE"),
            authenticatorData = ???,
            clientDataJsonBytes = clientDataJsonBytes,
          )
          val step4: steps.Step4 = steps.begin.next.get.next.get.next.get

          step4.validations shouldBe a [Failure[_]]
          step4.validations.failed.get shouldBe an [AssertionError]
          step4.next shouldBe a [Failure[_]]
        }
      }

      describe("7. Verify that the") {
        it("clientExtensions member of C is a subset of the extensions requested by the Relying Party.") {
          val failSteps = finishAssertion(
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

          val successSteps = finishAssertion(
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

        it("authenticatorExtensions member of C C is also a subset of the extensions requested by the Relying Party.") {
          val failSteps = finishAssertion(
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

          val successSteps = finishAssertion(
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

      describe("8. Verify that the RP ID hash in aData is the SHA-256 hash of the RP ID expected by the Relying Party.") {
        it("Fails if RP ID is different.") {
          val steps = finishAssertion(rpId = Defaults.rpId.copy(id = "root.evil"))
          val step8: steps.Step8 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get

          step8.validations shouldBe a [Failure[_]]
          step8.validations.failed.get shouldBe an [AssertionError]
          step8.next shouldBe a [Failure[_]]
        }

        it("Succeeds if RP ID is the same.") {
          val steps = finishAssertion()
          val step8: steps.Step8 = steps.begin.next.get.next.get.next.get.next.get.next.get.next.get.next.get

          step8.validations shouldBe a [Success[_]]
          step8.next shouldBe a [Success[_]]
        }
      }

      describe("9. Let hash be the result of computing a hash over the cData using the algorithm represented by the hashAlgorithm member of C.") {
        it("SHA-256 is allowed.") {
          val steps = finishAssertion()
          val step6: steps.Step6 = steps.begin.next.get.next.get.next.get.next.get.next.get

          step6.validations shouldBe a [Success[_]]
          step6.next shouldBe a [Success[_]]
          step6.clientDataJsonHash should equal (MessageDigest.getInstance("SHA-256").digest(Defaults.clientDataJsonBytes.toArray).toVector)
        }

        def checkForbidden(algorithm: String): Unit = {
          it(s"${algorithm} is forbidden.") {
            val steps = finishAssertion(
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

      it("10. Using the credential public key looked up in step 1, verify that sig is a valid signature over the binary concatenation of aData and hash.") {
        fail("Test not implemented.")
      }

      it("11. If all the above steps are successful, continue with the authentication ceremony as appropriate. Otherwise, fail the authentication ceremony.") {
        fail("Test not implemented.")
      }

    }

  }

}
