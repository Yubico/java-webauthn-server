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
import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.SerializationFeature
import com.fasterxml.jackson.databind.exc.ValueInstantiationException
import com.fasterxml.jackson.databind.node.ObjectNode
import com.fasterxml.jackson.databind.node.TextNode
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module
import com.yubico.internal.util.JacksonCodecs
import com.yubico.webauthn.AssertionRequest
import com.yubico.webauthn.AssertionResult
import com.yubico.webauthn.Generators._
import com.yubico.webauthn.RegisteredCredential
import com.yubico.webauthn.RegistrationResult
import com.yubico.webauthn.attestation.Attestation
import com.yubico.webauthn.attestation.Generators._
import com.yubico.webauthn.attestation.Transport
import com.yubico.webauthn.data.Generators._
import com.yubico.webauthn.extension.appid.AppId
import com.yubico.webauthn.extension.appid.Generators._
import org.junit.runner.RunWith
import org.scalacheck.Arbitrary
import org.scalatest.FunSpec
import org.scalatest.Matchers
import org.scalatestplus.junit.JUnitRunner
import org.scalatestplus.scalacheck.ScalaCheckDrivenPropertyChecks

@RunWith(classOf[JUnitRunner])
class JsonIoSpec
    extends FunSpec
    with Matchers
    with ScalaCheckDrivenPropertyChecks {

  def json: ObjectMapper =
    new ObjectMapper()
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

            decoded should equal(value)
          }
        }

        it("is identical after multiple serialization round-trips..") {
          forAll { value: A =>
            println(value)

            val encoded: String = json.writeValueAsString(value)
            println(encoded)

            val decoded: A = json.readValue(encoded, tpe)
            println(decoded)

            val recoded: String = json.writeValueAsString(decoded)
            println(recoded)

            decoded should equal(value)
            recoded should equal(encoded)
          }
        }
      }
    }

    test(new TypeReference[AppId]() {})
    test(new TypeReference[AssertionExtensionInputs]() {})
    test(new TypeReference[AssertionRequest]() {})
    test(new TypeReference[AssertionResult]() {})
    test(new TypeReference[Attestation]() {})
    test(new TypeReference[AttestationConveyancePreference]() {})
    test(new TypeReference[AttestationObject]() {})
    test(new TypeReference[AttestationType]() {})
    test(new TypeReference[AttestedCredentialData]() {})
    test(new TypeReference[AuthenticatorAssertionResponse]() {})
    test(new TypeReference[AuthenticatorAttachment]() {})
    test(new TypeReference[AuthenticatorAttestationResponse]() {})
    test(new TypeReference[AuthenticatorData]() {})
    test(new TypeReference[AuthenticatorDataFlags]() {})
    test(new TypeReference[AuthenticatorSelectionCriteria]() {})
    test(new TypeReference[AuthenticatorTransport]() {})
    test(new TypeReference[ClientAssertionExtensionOutputs]() {})
    test(new TypeReference[ClientRegistrationExtensionOutputs]() {})
    test(new TypeReference[CollectedClientData]() {})
    test(new TypeReference[COSEAlgorithmIdentifier]() {})
    test(
      new TypeReference[PublicKeyCredential[
        AuthenticatorAssertionResponse,
        ClientAssertionExtensionOutputs,
      ]]() {}
    )
    test(
      new TypeReference[PublicKeyCredential[
        AuthenticatorAttestationResponse,
        ClientRegistrationExtensionOutputs,
      ]]() {}
    )
    test(new TypeReference[PublicKeyCredentialCreationOptions]() {})
    test(new TypeReference[PublicKeyCredentialDescriptor]() {})
    test(new TypeReference[PublicKeyCredentialParameters]() {})
    test(new TypeReference[PublicKeyCredentialRequestOptions]() {})
    test(new TypeReference[PublicKeyCredentialType]() {})
    test(new TypeReference[RegisteredCredential]() {})
    test(new TypeReference[RegistrationExtensionInputs]() {})
    test(new TypeReference[RegistrationResult]() {})
    test(new TypeReference[RelyingPartyIdentity]() {})
    test(new TypeReference[TokenBindingInfo]() {})
    test(new TypeReference[TokenBindingStatus]() {})
    test(new TypeReference[Transport]() {})
    test(new TypeReference[UserIdentity]() {})
    test(new TypeReference[UserVerificationRequirement]() {})
  }

  describe("The class PublicKeyCredential") {
    it(
      "has an alternative parseRegistrationResponseJson function as an alias."
    ) {
      def test[A](tpe: TypeReference[A])(implicit a: Arbitrary[A]): Unit = {
        forAll { value: A =>
          val encoded: String = json.writeValueAsString(value)
          val decoded: A = json.readValue(encoded, tpe)
          val altDecoded =
            PublicKeyCredential.parseRegistrationResponseJson(encoded)
          val altRecoded: String = json.writeValueAsString(altDecoded)

          altDecoded should equal(decoded)
          altRecoded should equal(encoded)
        }
      }
      test(
        new TypeReference[PublicKeyCredential[
          AuthenticatorAttestationResponse,
          ClientRegistrationExtensionOutputs,
        ]]() {}
      )
    }

    it(
      "has an alternative parseAuthenticationResponseJson function as an alias."
    ) {
      def test[A](tpe: TypeReference[A])(implicit a: Arbitrary[A]): Unit = {
        forAll { value: A =>
          val encoded: String = json.writeValueAsString(value)
          val decoded: A = json.readValue(encoded, tpe)
          val altDecoded =
            PublicKeyCredential.parseAssertionResponseJson(encoded)
          val altRecoded: String = json.writeValueAsString(altDecoded)

          altDecoded should equal(decoded)
          altRecoded should equal(encoded)
        }
      }
      test(
        new TypeReference[PublicKeyCredential[
          AuthenticatorAssertionResponse,
          ClientAssertionExtensionOutputs,
        ]]() {}
      )
    }

    it("allows rawId to be present without id.") {
      def test[P <: PublicKeyCredential[_, _]](tpe: TypeReference[P])(implicit
          a: Arbitrary[P]
      ): Unit = {
        forAll { value: P =>
          val encoded: String = json.writeValueAsString(value)
          val decoded = json.readTree(encoded)
          decoded
            .asInstanceOf[ObjectNode]
            .set[ObjectNode]("rawId", new TextNode(value.getId.getBase64Url))
            .remove("id")
          val reencoded = json.writeValueAsString(decoded)
          val restored: P = json.readValue(reencoded, tpe)

          restored.getId should equal(value.getId)
          restored should equal(value)
        }
      }
      test(
        new TypeReference[PublicKeyCredential[
          AuthenticatorAssertionResponse,
          ClientAssertionExtensionOutputs,
        ]]() {}
      )
      test(
        new TypeReference[PublicKeyCredential[
          AuthenticatorAttestationResponse,
          ClientRegistrationExtensionOutputs,
        ]]() {}
      )
    }

    it("allows id to be present without rawId.") {
      def test[P <: PublicKeyCredential[_, _]](tpe: TypeReference[P])(implicit
          a: Arbitrary[P]
      ): Unit = {
        forAll { value: P =>
          val encoded: String = json.writeValueAsString(value)
          val decoded = json.readTree(encoded)
          decoded
            .asInstanceOf[ObjectNode]
            .set[ObjectNode]("id", new TextNode(value.getId.getBase64Url))
            .remove("rawId")
          val reencoded = json.writeValueAsString(decoded)
          val restored: P = json.readValue(reencoded, tpe)

          restored should equal(value)
        }
      }
      test(
        new TypeReference[PublicKeyCredential[
          AuthenticatorAssertionResponse,
          ClientAssertionExtensionOutputs,
        ]]() {}
      )
      test(
        new TypeReference[PublicKeyCredential[
          AuthenticatorAttestationResponse,
          ClientRegistrationExtensionOutputs,
        ]]() {}
      )
    }

    it("allows both id and rawId to be present if equal.") {
      def test[P <: PublicKeyCredential[_, _]](tpe: TypeReference[P])(implicit
          a: Arbitrary[P]
      ): Unit = {
        forAll { value: P =>
          val encoded: String = json.writeValueAsString(value)
          val decoded = json.readTree(encoded)
          decoded
            .asInstanceOf[ObjectNode]
            .set("id", new TextNode(value.getId.getBase64Url))
          decoded
            .asInstanceOf[ObjectNode]
            .set("rawId", new TextNode(value.getId.getBase64Url))
          val reencoded = json.writeValueAsString(decoded)
          val restored: P = json.readValue(reencoded, tpe)

          restored should equal(value)
        }
      }
      test(
        new TypeReference[PublicKeyCredential[
          AuthenticatorAssertionResponse,
          ClientAssertionExtensionOutputs,
        ]]() {}
      )
      test(
        new TypeReference[PublicKeyCredential[
          AuthenticatorAttestationResponse,
          ClientRegistrationExtensionOutputs,
        ]]() {}
      )
    }

    it("does not allow both id and rawId to be absent.") {
      def test[P <: PublicKeyCredential[_, _]](tpe: TypeReference[P])(implicit
          a: Arbitrary[P]
      ): Unit = {
        forAll { value: P =>
          val encoded: String = json.writeValueAsString(value)
          val decoded = json.readTree(encoded).asInstanceOf[ObjectNode]
          decoded.remove("id")
          decoded.remove("rawId")
          val reencoded = json.writeValueAsString(decoded)

          an[ValueInstantiationException] should be thrownBy {
            json.readValue(reencoded, tpe)
          }
        }
      }

      test(
        new TypeReference[PublicKeyCredential[
          AuthenticatorAssertionResponse,
          ClientAssertionExtensionOutputs,
        ]]() {}
      )
      test(
        new TypeReference[PublicKeyCredential[
          AuthenticatorAttestationResponse,
          ClientRegistrationExtensionOutputs,
        ]]() {}
      )
    }

    it("does not allow both id and rawId to be present and not equal.") {
      def test[P <: PublicKeyCredential[_, _]](tpe: TypeReference[P])(implicit
          a: Arbitrary[P]
      ): Unit = {
        forAll { value: P =>
          val modId = new ByteArray(
            if (value.getId.getBytes.isEmpty)
              Array(0)
            else
              value.getId.getBytes
                .updated(0, (value.getId.getBytes()(0) + 1 % 127).byteValue)
          )

          val encoded: String = json.writeValueAsString(value)
          val decoded = json.readTree(encoded)
          decoded
            .asInstanceOf[ObjectNode]
            .set[ObjectNode]("id", new TextNode(value.getId.getBase64Url))
            .set[ObjectNode]("rawId", new TextNode(modId.getBase64Url))
          val reencoded = json.writeValueAsString(decoded)

          an[ValueInstantiationException] should be thrownBy {
            json.readValue(reencoded, tpe)
          }
        }
      }

      test(
        new TypeReference[PublicKeyCredential[
          AuthenticatorAssertionResponse,
          ClientAssertionExtensionOutputs,
        ]]() {}
      )
      test(
        new TypeReference[PublicKeyCredential[
          AuthenticatorAttestationResponse,
          ClientRegistrationExtensionOutputs,
        ]]() {}
      )
    }
  }

  describe("The class PublicKeyCredentialCreationOptions") {
    it("""has a toCredentialsCreateJson() method which returns a JSON object with the PublicKeyCredentialCreationOptions set as a top-level "publicKey" property.""") {
      forAll { pkcco: PublicKeyCredentialCreationOptions =>
        println(pkcco)
        val jsonValue =
          JacksonCodecs.json.readTree(pkcco.toCredentialsCreateJson)
        jsonValue.get("publicKey") should not be null
        JacksonCodecs.json.treeToValue(
          jsonValue.get("publicKey"),
          classOf[PublicKeyCredentialCreationOptions],
        ) should equal(pkcco)
      }
    }

    describe("has a toJson() method and a fromJson(String) factory method") {
      it("which behave like a Jackson ObjectMapper.") {
        forAll { req: PublicKeyCredentialCreationOptions =>
          println(req)
          val json1 = req.toJson
          val json2 = JacksonCodecs.json.writeValueAsString(req)
          json1 should equal(json2)

          val parsed1 = PublicKeyCredentialCreationOptions.fromJson(json1)
          val parsed2 = JacksonCodecs.json.readValue(
            json2,
            classOf[PublicKeyCredentialCreationOptions],
          )
          parsed1 should equal(parsed2)
        }
      }

      it("which are stable over multiple serialization round-trips.") {
        forAll { req: PublicKeyCredentialCreationOptions =>
          println(req)
          val encoded = req.toJson
          val decoded = PublicKeyCredentialCreationOptions.fromJson(encoded)
          val reencoded = decoded.toJson
          val redecoded = PublicKeyCredentialCreationOptions.fromJson(reencoded)

          decoded should equal(req)
          redecoded should equal(req)
          encoded should equal(reencoded)
        }
      }
    }
  }

  describe("The class PublicKeyCredentialRequestOptions") {
    it("""has a toCredentialsGetJson() method which returns a JSON object with the PublicKeyCredentialGetOptions set as a top-level "publicKey" property.""") {
      forAll { pkcro: PublicKeyCredentialRequestOptions =>
        println(pkcro)
        val jsonValue = JacksonCodecs.json.readTree(pkcro.toCredentialsGetJson)
        jsonValue.get("publicKey") should not be null
        JacksonCodecs.json.treeToValue(
          jsonValue.get("publicKey"),
          classOf[PublicKeyCredentialRequestOptions],
        ) should equal(pkcro)
      }
    }
  }

  describe("The class AssertionRequest") {
    it("""has a toCredentialsGetJson() method which returns a JSON object with the PublicKeyCredentialGetOptions set as a top-level "publicKey" property.""") {
      forAll { req: AssertionRequest =>
        println(req)

        val jsonValue = JacksonCodecs.json.readTree(req.toCredentialsGetJson)
        jsonValue.get("publicKey") should not be null
        JacksonCodecs.json.treeToValue(
          jsonValue.get("publicKey"),
          classOf[PublicKeyCredentialRequestOptions],
        ) should equal(req.getPublicKeyCredentialRequestOptions)
      }
    }

    describe("has a toJson() method and a fromJson(String) factory method") {
      it("which behave like a Jackson ObjectMapper.") {
        forAll { req: AssertionRequest =>
          println(req)
          val json1 = req.toJson
          val json2 = JacksonCodecs.json.writeValueAsString(req)

          val parsed1 = AssertionRequest.fromJson(json1)
          val parsed2 =
            JacksonCodecs.json.readValue(json2, classOf[AssertionRequest])
          json1 should equal(json2)
          parsed1 should equal(parsed2)
        }
      }

      it("which are stable over multiple serialization round-trips.") {
        forAll { req: AssertionRequest =>
          println(req)
          val encoded = req.toJson
          val decoded = AssertionRequest.fromJson(encoded)
          val reencoded = decoded.toJson
          val redecoded = AssertionRequest.fromJson(reencoded)

          decoded should equal(req)
          redecoded should equal(req)
          encoded should equal(reencoded)
        }
      }
    }
  }

}
