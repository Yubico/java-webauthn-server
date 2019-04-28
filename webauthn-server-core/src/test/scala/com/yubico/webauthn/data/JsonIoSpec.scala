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

package com.yubico.webauthn.data

import com.fasterxml.jackson.annotation.JsonInclude.Include
import com.fasterxml.jackson.core.`type`.TypeReference
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module
import com.yubico.webauthn.RegistrationResult
import com.yubico.webauthn.AssertionResult
import com.yubico.webauthn.AssertionRequest
import com.yubico.webauthn.Generators._
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
    .configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false)
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
    test(new TypeReference[AttestedCredentialData]() {})
    test(new TypeReference[AttestationObject]() {})
    test(new TypeReference[AttestationType]() {})
    test(new TypeReference[AuthenticatorDataFlags]() {})
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

  describe("The class PublicKeyCredential") {
    it("has an alternative parseRegistrationResponseJson function as an alias.") {
      def test[A](tpe: TypeReference[A])(implicit a: Arbitrary[A]): Unit = {
        forAll { value: A =>
          val encoded: String = json.writeValueAsString(value)
          val decoded: A = json.readValue(encoded, tpe)
          val altDecoded = PublicKeyCredential.parseRegistrationResponseJson(encoded)
          val altRecoded: String = json.writeValueAsString(altDecoded)

          altDecoded should equal (decoded)
          altRecoded should equal (encoded)
        }
      }
      test(new TypeReference[PublicKeyCredential[AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs]](){})
    }

    it("has an alternative parseAuthenticationResponseJson function as an alias.") {
      def test[A](tpe: TypeReference[A])(implicit a: Arbitrary[A]): Unit = {
        forAll { value: A =>
          val encoded: String = json.writeValueAsString(value)
          val decoded: A = json.readValue(encoded, tpe)
          val altDecoded = PublicKeyCredential.parseAssertionResponseJson(encoded)
          val altRecoded: String = json.writeValueAsString(altDecoded)

          altDecoded should equal (decoded)
          altRecoded should equal (encoded)
        }
      }
      test(new TypeReference[PublicKeyCredential[AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs]](){})
    }
  }

}
