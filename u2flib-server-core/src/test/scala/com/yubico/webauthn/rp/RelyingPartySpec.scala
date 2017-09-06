package com.yubico.webauthn.rp

import java.security.MessageDigest

import com.fasterxml.jackson.core.JsonParseException
import com.fasterxml.jackson.databind.node.JsonNodeFactory
import com.fasterxml.jackson.databind.node.ObjectNode
import com.yubico.scala.util.JavaConverters._
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding
import com.yubico.webauthn.RelyingParty
import com.yubico.webauthn.FinishRegistrationSteps
import com.yubico.webauthn.data.ArrayBuffer
import com.yubico.webauthn.data.AuthenticationExtensions
import com.yubico.webauthn.data.MakePublicKeyCredentialOptions
import com.yubico.webauthn.data.PublicKeyCredentialParameters
import com.yubico.webauthn.data.PublicKey
import com.yubico.webauthn.data.RelyingPartyIdentity
import com.yubico.webauthn.data.UserIdentity
import com.yubico.webauthn.data.Base64UrlString
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria
import com.yubico.webauthn.data.impl.PublicKeyCredential
import com.yubico.webauthn.data.impl.AuthenticatorAttestationResponse
import com.yubico.webauthn.util.BinaryUtil
import com.yubico.webauthn.util.WebAuthnCodecs
import org.junit.runner.RunWith
import org.scalatest.FunSpec
import org.scalatest.Matchers
import org.scalatest.junit.JUnitRunner

import scala.util.Failure
import scala.util.Success


@RunWith(classOf[JUnitRunner])
class RelyingPartySpec extends FunSpec with Matchers {

  def jsonFactory: JsonNodeFactory = JsonNodeFactory.instance

  describe("§6. Relying Party Operations") {

    object Defaults {
      val challengeBase64 = "s1lKsm0KoJpzXM2YsHpOLQ"
      val attestationObject: ArrayBuffer = BinaryUtil.fromHex("a368617574684461746159012c49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d976341000000000000000000000000000000000000000000a20008a6c78eaa5777597eca3d84575e107e1866a865062c49fb73f462d5a5d6ca39165024be6b611c2a19ca865ccfa01cc12c9944233389cd8229daba3f0c41383f18e745f248ca7fb54f47802e42125f136c1d22615d64ccb9c8cdbdc70fed396a4db693300d608ce878951852e7a9e0cb4fdee93ec9d5901512181c4a6999fafe775afd0813c5bb5f151c8d1bde2a90dd88df9b2d5a60ec51b477fdf0748c7bc00ca363616c6765455332353661785820399b6270c8ba53708a4806b08f48f1b790f3b3c990fcdf108a89651eaf0aefa561795820e448eab4cce5a8dabf73a37a6bea31e4e796ca545b93443c72fbfc09417e522f63666d74686669646f2d7532666761747453746d74a26378356381590135308201313081d8a00302010202045aeaf239300a06082a8648ce3d0403023021311f301d0603550403131646697265666f782055324620536f667420546f6b656e301e170d3137303930333135333430345a170d3137303930353135333430345a3021311f301d0603550403131646697265666f782055324620536f667420546f6b656e3059301306072a8648ce3d020106082a8648ce3d030107034200045e8336fc54facfab94778b7a904a1d5083782875c147844c5ae3fbd69e882a9368579b9a5bb51db981aab66e8267c914a100cd3b05794c206bb95aca5543691c300a06082a8648ce3d040302034800304502210082a6d219be7d0b0c61f68acef9e7045bdd05ec70a16d93e411ff462068df5b9d0220487de014bad0633185c29ac3110563e40cec02c2225bed51ffb56bda75bd08bb6373696758473045022100cbb9597de6317b8da61811c8fe6ea94c2f40afe1acba217656c8d7872f159c3b022029e484160cce0a6f7faf3d9ed0fc3c9aff9fd237acb4adb1b3bcf8c2057bd1b6").get
      val requestedExtensions: AuthenticationExtensions = jsonFactory.objectNode()
      val clientDataJson: String = s"""{"challenge":"${challengeBase64}","hashAlgorithm":"SHA-256","origin":"localhost"}"""
      val clientDataJsonBytes: ArrayBuffer = clientDataJson.getBytes("UTF-8").toVector
      val clientExtensionResults: AuthenticationExtensions = jsonFactory.objectNode()
      val credentialId: ArrayBuffer = BinaryUtil.fromHex("00085b9bfacca2df2ad6efef962dd05190249b429cc35091785bd6f80e68cb2fee69a5c0796c2c20ca8e634a521481995cc6c6989d4f91f43151392bcaa486d8072e399094e9d2e14a7065a79b8f4bc9610043ab0bd3383c9c041a460c741db5b36e5c85e9727ee8b1803f335666abee049af72ee1bc18a9ee782404ad31f59eb332db488a2a779a3b4a17798cb1b4790e92edc99cde9edbb617e35f6135c7026ca5").get

      val rpId = RelyingPartyIdentity(name = "Test party", id = "localhost")
      val userId = UserIdentity(null, null, null)
    }

    def finishRegistration(
      allowSelfAttestation: Boolean = false,
      authenticatorRequirements: Option[AuthenticatorSelectionCriteria] = None,
      callerTokenBindingId: Option[String] = None,
      challenge: ArrayBuffer = U2fB64Encoding.decode(Defaults.challengeBase64).toVector,
      clientDataJsonBytes: ArrayBuffer = Defaults.clientDataJsonBytes,
      requestedExtensions: Option[AuthenticationExtensions] = None,
      clientExtensionResults: AuthenticationExtensions = Defaults.clientExtensionResults,
      origin: String = Defaults.rpId.id,
      rpId: RelyingPartyIdentity = Defaults.rpId,
    ): FinishRegistrationSteps = {

      val request = MakePublicKeyCredentialOptions(
        rp = rpId,
        user = Defaults.userId,
        challenge = challenge,
        pubKeyCredParams = List(PublicKeyCredentialParameters(`type` = PublicKey, alg = -7L)),
        extensions = requestedExtensions.asJava,
      )

      val response = PublicKeyCredential(
        Defaults.credentialId,
        AuthenticatorAttestationResponse(Defaults.attestationObject, clientDataJsonBytes),
        clientExtensionResults,
      )

      new RelyingParty(
        allowSelfAttestation = allowSelfAttestation,
        authenticatorRequirements = authenticatorRequirements.asJava,
        challengeGenerator = null,
        origin = origin,
        preferredPubkeyParams = request.pubKeyCredParams,
        rp = rpId,
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
          val tokenA: Base64UrlString = U2fB64Encoding.encode("foo".getBytes("UTF-8"))
          val tokenB: Base64UrlString = U2fB64Encoding.encode("bar".getBytes("UTF-8"))

          it("Verification succeeds if neither side specifies token binding ID.") {
            val steps = finishRegistration()
            val step4: steps.Step4 = steps.begin.next.get.next.get.next.get

            step4.validations shouldBe a [Success[_]]
            step4.next shouldBe a [Success[_]]
          }

          it("Verification fails if caller specifies token binding ID but attestation does not.") {
            val steps = finishRegistration(callerTokenBindingId = Some(tokenA))
            val step4: steps.Step4 = steps.begin.next.get.next.get.next.get

            step4.validations shouldBe a [Failure[_]]
            step4.validations.failed.get shouldBe an [AssertionError]
            step4.next shouldBe a [Failure[_]]
          }

          it("Verification fails if attestation specifies token binding ID but caller does not.") {
            val steps = finishRegistration(???)
            val step4: steps.Step4 = steps.begin.next.get.next.get.next.get

            step4.validations shouldBe a [Failure[_]]
            step4.validations.failed.get shouldBe an [AssertionError]
            step4.next shouldBe a [Failure[_]]
          }

          it("Verification fails if attestation and caller specify different token binding IDs.") {
            val steps = finishRegistration(???, callerTokenBindingId = Some(tokenB))
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

        it("9. Determine the attestation statement format by performing an USASCII case-sensitive match on fmt against the set of supported WebAuthn Attestation Statement Format Identifier values. The up-to-date list of registered WebAuthn Attestation Statement Format Identifier values is maintained in the in the IANA registry of the same name [WebAuthn-Registries].") {
          fail("Not implemented.")
        }

        it("10. Verify that attStmt is a correct, validly-signed attestation statement, using the attestation statement format fmt’s verification procedure given authenticator data authData and the hash of the serialized client data computed in step 6.") {
          fail("Not implemented.")
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
          fail("Not implemented.")
        }

        it("14. If the attestation statement attStmt successfully verified but is not trustworthy per step 12 above, the Relying Party SHOULD fail the registration ceremony.") {
          fail("Not implemented.")
        }

        it("15. NOTE: However, if permitted by policy, the Relying Party MAY register the credential ID and credential public key but treat the credential as one with self attestation (see §5.3.3 Attestation Types). If doing so, the Relying Party is asserting there is no cryptographic proof that the public key credential has been generated by a particular authenticator model. See [FIDOSecRef] and [UAFProtocol] for a more detailed discussion.") {
          fail("Not implemented.")
        }

        it("16. If verification of the attestation statement failed, the Relying Party MUST fail the registration ceremony.") {
          fail("Not implemented.")
        }

      }

    }

  }

}
