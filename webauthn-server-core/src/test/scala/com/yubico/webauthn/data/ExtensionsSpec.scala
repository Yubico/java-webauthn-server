package com.yubico.webauthn.data

import com.fasterxml.jackson.databind.node.ObjectNode
import com.yubico.internal.util.JacksonCodecs
import com.yubico.scalacheck.gen.JacksonGenerators.arbitraryObjectNode
import com.yubico.webauthn.data.Extensions.LargeBlob.LargeBlobAuthenticationOutput
import com.yubico.webauthn.data.Extensions.LargeBlob.LargeBlobRegistrationInput
import com.yubico.webauthn.data.Extensions.LargeBlob.LargeBlobRegistrationInput.LargeBlobSupport
import com.yubico.webauthn.data.Extensions.LargeBlob.LargeBlobRegistrationOutput
import com.yubico.webauthn.data.Generators.arbitraryClientRegistrationExtensionOutputs
import com.yubico.webauthn.data.Generators.arbitraryRegistrationExtensionInputs
import com.yubico.webauthn.extension.appid.AppId
import com.yubico.webauthn.test.RealExamples
import org.junit.runner.RunWith
import org.scalacheck.Arbitrary.arbitrary
import org.scalacheck.Gen
import org.scalatest.FunSpec
import org.scalatest.Matchers
import org.scalatestplus.junit.JUnitRunner
import org.scalatestplus.scalacheck.ScalaCheckDrivenPropertyChecks

import java.nio.charset.StandardCharsets
import scala.jdk.CollectionConverters.IteratorHasAsScala
import scala.jdk.CollectionConverters.SetHasAsScala
import scala.jdk.OptionConverters.RichOptional

@RunWith(classOf[JUnitRunner])
class ExtensionsSpec
    extends FunSpec
    with Matchers
    with ScalaCheckDrivenPropertyChecks {

  describe("RegistrationExtensionInputs") {
    describe("has a getExtensionIds() method which") {
      it("contains exactly the names of contained extensions.") {
        forAll { input: RegistrationExtensionInputs =>
          val json = JacksonCodecs.json().valueToTree[ObjectNode](input)
          val jsonKeyNames = json.fieldNames.asScala.toList
          val extensionIds = input.getExtensionIds

          jsonKeyNames.length should equal(extensionIds.size)
          jsonKeyNames.toSet should equal(extensionIds.asScala)
        }
      }
    }

    it("can deserialize from JSON with unknown extensions.") {
      val json = JacksonCodecs.json()
      forAll(Generators.Extensions.registrationExtensionInputsJson()) {
        encoded: ObjectNode =>
          println(encoded)
          val decoded =
            json.treeToValue(encoded, classOf[RegistrationExtensionInputs])

          val reencoded = json.writeValueAsString(decoded)
          val redecoded =
            json.readValue(reencoded, classOf[RegistrationExtensionInputs])
          val rereencoded = json.writeValueAsString(redecoded)

          decoded should not be null
          redecoded should equal(decoded)
          rereencoded should equal(reencoded)
      }
    }

    it("can deserialize from a known JSON example.") {
      val json = JacksonCodecs.json()
      val encoded =
        """{
          |"appidExclude": "https://example.org",
          |"credProps": true,
          |"largeBlob": {
          |  "support": "required"
          |},
          |"uvm": true
          |}""".stripMargin

      val decoded =
        json.readValue(encoded, classOf[RegistrationExtensionInputs])

      val reencoded = json.writeValueAsString(decoded)
      val redecoded =
        json.readValue(reencoded, classOf[RegistrationExtensionInputs])

      decoded should not be null
      decoded.getExtensionIds.asScala should equal(
        Set("appidExclude", "credProps", "largeBlob", "uvm")
      )
      decoded.getAppidExclude.toScala should equal(
        Some(new AppId("https://example.org"))
      )
      decoded.getLargeBlob.toScala should equal(
        Some(new LargeBlobRegistrationInput(LargeBlobSupport.REQUIRED))
      )
      decoded.getUvm should be(true)

      redecoded should equal(decoded)
      json.readTree(reencoded) should equal(json.readTree(encoded))
    }

    it("omits credProps from JSON serialization when false.") {
      forAll(
        Generators.Extensions
          .registrationExtensionInputs(credPropsGen = Gen.const(None))
      ) { inpt: RegistrationExtensionInputs =>
        val json = JacksonCodecs.json().valueToTree[ObjectNode](inpt)
        json.has(Extensions.CredentialProperties.EXTENSION_ID) should be(false)
      }
    }

    it("omits uvm from JSON serialization when false.") {
      forAll(
        Generators.Extensions
          .registrationExtensionInputs(uvmGen = Gen.const(None))
      ) { input: RegistrationExtensionInputs =>
        val json = JacksonCodecs.json().valueToTree[ObjectNode](input)
        json.has(Extensions.Uvm.EXTENSION_ID) should be(false)
      }
    }
  }

  describe("ClientRegistrationExtensionOutputs") {
    describe("has a getExtensionIds() method which") {
      it("contains exactly the names of contained extensions.") {
        forAll { input: ClientRegistrationExtensionOutputs =>
          val json = JacksonCodecs.json().valueToTree[ObjectNode](input)
          val jsonKeyNames = json.fieldNames.asScala.toList
          val extensionIds = input.getExtensionIds

          println(input)
          println(json)

          jsonKeyNames.length should equal(extensionIds.size)
          jsonKeyNames.toSet should equal(extensionIds.asScala)
        }
      }
    }

    it("can deserialize from JSON with unknown extensions.") {
      val json = JacksonCodecs.json()
      forAll(
        Generators.Extensions.clientRegistrationExtensionOutputs(),
        arbitrary[ObjectNode],
      ) { (clientExtensionOutputs, unknownOutputs) =>
        val encoded = json.valueToTree[ObjectNode](clientExtensionOutputs)
        encoded.setAll(unknownOutputs)

        println(encoded)
        val decoded = json.treeToValue(
          encoded,
          classOf[ClientRegistrationExtensionOutputs],
        )

        val reencoded = json.writeValueAsString(decoded)
        val redecoded = json.readValue(
          reencoded,
          classOf[ClientRegistrationExtensionOutputs],
        )

        decoded should not be null
        redecoded should equal(decoded)
      }
    }

    it("omits appidExclude from JSON serialization when false.") {
      forAll(
        Generators.Extensions
          .clientRegistrationExtensionOutputs(appidExcludeGen =
            Gen.option(false)
          )
      ) { input: ClientRegistrationExtensionOutputs =>
        val json = JacksonCodecs.json().valueToTree[ObjectNode](input)
        println(json)
        json.has(Extensions.AppidExclude.EXTENSION_ID) should be(false)
      }
    }

    it("can deserialize a real largeBlob write example.") {
      val testData = RealExamples.LargeBlobWrite
      val registrationCred = testData.attestation.credential
      val assertionCred = testData.assertion.credential

      registrationCred.getClientExtensionResults.getExtensionIds.asScala should equal(
        Set("largeBlob")
      )
      registrationCred.getClientExtensionResults.getLargeBlob.toScala should equal(
        Some(new LargeBlobRegistrationOutput(true))
      )

      assertionCred.getClientExtensionResults.getExtensionIds.asScala should equal(
        Set("appid", "largeBlob")
      )
      assertionCred.getClientExtensionResults.getLargeBlob.toScala should equal(
        Some(new LargeBlobAuthenticationOutput(null, true))
      )
    }

    it("can deserialize a real largeBlob read example.") {
      val testData = RealExamples.LargeBlobRead
      val registrationCred = testData.attestation.credential
      val assertionCred = testData.assertion.credential

      registrationCred.getClientExtensionResults.getExtensionIds.asScala should equal(
        Set("largeBlob")
      )
      registrationCred.getClientExtensionResults.getLargeBlob.toScala should equal(
        Some(new LargeBlobRegistrationOutput(true))
      )

      assertionCred.getClientExtensionResults.getExtensionIds.asScala should equal(
        Set("appid", "largeBlob")
      )
      assertionCred.getClientExtensionResults.getLargeBlob.toScala should equal(
        Some(
          new LargeBlobAuthenticationOutput(
            new ByteArray("Hello, World!".getBytes(StandardCharsets.UTF_8)),
            null,
          )
        )
      )
    }
  }

}
