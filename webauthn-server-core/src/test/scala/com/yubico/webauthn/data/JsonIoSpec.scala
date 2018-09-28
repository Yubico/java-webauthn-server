package com.yubico.webauthn.data

import com.fasterxml.jackson.annotation.JsonInclude.Include
import com.fasterxml.jackson.core.`type`.TypeReference
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module
import com.yubico.webauthn.data.Generators._
import com.yubico.webauthn.extension.appid.AppId
import com.yubico.webauthn.extension.appid.Generators._
import org.junit.runner.RunWith
import org.scalacheck.Arbitrary
import org.scalatest.FunSpec
import org.scalatest.Matchers
import org.scalatest.junit.JUnitRunner
import org.scalatest.prop.GeneratorDrivenPropertyChecks


@RunWith(classOf[JUnitRunner])
class JsonIoSpec extends FunSpec with Matchers with GeneratorDrivenPropertyChecks {

  def json: ObjectMapper = new ObjectMapper()
    .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true)
    .setSerializationInclusion(Include.NON_ABSENT)
    .registerModule(new Jdk8Module())

  describe("The class") {

    def test[A](tpe: TypeReference[A])(implicit a: Arbitrary[A]): Unit = {
      val cn = tpe.getType.getTypeName
      describe(s"${cn}") {
        it("can be serialized to JSON.") {
          forAll { value: A =>
            val encoded: String = json.writeValueAsString(value)

            encoded should not be empty
          }
        }

        it("can be deserialized from JSON.") {
          forAll { value: A =>
            val encoded: String = json.writeValueAsString(value)
            val decoded: A = json.readValue(encoded, tpe)

            decoded should equal (value)
          }
        }

        it("is identical after multiple serialization round-trips..") {
          forAll { value: A =>
            val encoded: String = json.writeValueAsString(value)
            val decoded: A = json.readValue(encoded, tpe)
            val recoded: String = json.writeValueAsString(decoded)

            decoded should equal (value)
            recoded should equal (encoded)
          }
        }
      }
    }

    test(new TypeReference[AppId]() {})
    test(new TypeReference[AssertionExtensionInputs]() {})
    test(new TypeReference[AssertionRequest]() {})
    test(new TypeReference[AssertionResult]() {})
    test(new TypeReference[AttestationConveyancePreference]() {})
    test(new TypeReference[AttestationData]() {})
    test(new TypeReference[AttestationObject]() {})
    test(new TypeReference[AttestationType]() {})
    test(new TypeReference[AuthenticationDataFlags]() {})
    test(new TypeReference[AuthenticatorAssertionResponse]() {})
    test(new TypeReference[AuthenticatorAttachment]() {})
    test(new TypeReference[AuthenticatorAttestationResponse]() {})
    test(new TypeReference[AuthenticatorData]() {})
    test(new TypeReference[AuthenticatorSelectionCriteria]() {})
    test(new TypeReference[AuthenticatorTransport]() {})
    test(new TypeReference[COSEAlgorithmIdentifier]() {})
    test(new TypeReference[ClientAssertionExtensionOutputs]() {})
    test(new TypeReference[ClientRegistrationExtensionOutputs]() {})
    test(new TypeReference[CollectedClientData]() {})
    test(new TypeReference[PublicKeyCredential[AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs]]() {})
    test(new TypeReference[PublicKeyCredential[AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs]]() {})
    test(new TypeReference[PublicKeyCredentialCreationOptions]() {})
    test(new TypeReference[PublicKeyCredentialDescriptor]() {})
    test(new TypeReference[PublicKeyCredentialParameters]() {})
    test(new TypeReference[PublicKeyCredentialRequestOptions]() {})
    test(new TypeReference[PublicKeyCredentialType]() {})
    test(new TypeReference[RegistrationExtensionInputs]() {})
    test(new TypeReference[RegistrationResult]() {})
    test(new TypeReference[RelyingPartyIdentity]() {})
    test(new TypeReference[TokenBindingInfo]() {})
    test(new TypeReference[TokenBindingStatus]() {})
    test(new TypeReference[UserIdentity]() {})
    test(new TypeReference[UserVerificationRequirement]() {})
  }

}
