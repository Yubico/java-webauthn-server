package com.yubico.webauthn.data

import com.yubico.webauthn.WebAuthnCodecs
import com.yubico.webauthn.data.Generators._
import org.junit.runner.RunWith
import org.scalacheck.Arbitrary
import org.scalatest.FunSpec
import org.scalatest.Matchers
import org.scalatest.junit.JUnitRunner
import org.scalatest.prop.GeneratorDrivenPropertyChecks


@RunWith(classOf[JUnitRunner])
class JsonIoSpec extends FunSpec with Matchers with GeneratorDrivenPropertyChecks {

  describe("The class") {

    def test[A](clazz: Class[A], className: Option[String] = None)(implicit a: Arbitrary[A]) = {
      val cn = className getOrElse clazz.getSimpleName
      describe(s"${cn}") {
        it("can be serialized to JSON.") {
          forAll { value: A =>
            val encoded: String = WebAuthnCodecs.json().writeValueAsString(value)

            encoded should not be empty
          }
        }

        it("can be deserialized from JSON.") {
          forAll { value: A =>
            val encoded: String = WebAuthnCodecs.json().writeValueAsString(value)
            val decoded: A = WebAuthnCodecs.json().readValue(encoded, clazz)

            decoded should equal (value)
          }
        }

        it("is identical after multiple serialization round-trips..") {
          forAll { value: A =>
            val encoded: String = WebAuthnCodecs.json().writeValueAsString(value)
            val decoded: A = WebAuthnCodecs.json().readValue(encoded, clazz)
            val recoded: String = WebAuthnCodecs.json().writeValueAsString(decoded)

            decoded should equal (value)
            recoded should equal (encoded)
          }
        }
      }
    }

    test(classOf[AssertionRequest])
    test(classOf[AssertionResult])
    test(classOf[AttestationConveyancePreference])
    test(classOf[AttestationData])
    test(classOf[AttestationObject])
    test(classOf[AttestationType])
    test(classOf[AuthenticationDataFlags])
    test(classOf[AuthenticatorAssertionResponse])
    test(classOf[AuthenticatorAttachment])
    test(classOf[AuthenticatorAttestationResponse])
    test(classOf[AuthenticatorData])
    test(classOf[AuthenticatorSelectionCriteria])
    test(classOf[AuthenticatorTransport])
    test(classOf[COSEAlgorithmIdentifier])
    test(classOf[CollectedClientData])
    test(classOf[PublicKeyCredential[AuthenticatorAssertionResponse]], Some("PublicKeyCredential[AuthenticatorAssertionResponse]"))
    test(classOf[PublicKeyCredential[AuthenticatorAttestationResponse]], Some("PublicKeyCredential[AuthenticatorAttestationResponse]"))
    test(classOf[PublicKeyCredentialCreationOptions])
    test(classOf[PublicKeyCredentialDescriptor])
    test(classOf[PublicKeyCredentialParameters])
    test(classOf[PublicKeyCredentialRequestOptions])
    test(classOf[PublicKeyCredentialType])
    test(classOf[RegistrationResult])
    test(classOf[RelyingPartyIdentity])
    test(classOf[TokenBindingInfo])
    test(classOf[TokenBindingStatus])
    test(classOf[UserIdentity])
    test(classOf[UserVerificationRequirement])
  }

}
