package com.yubico.webauthn.data

import com.yubico.fido.metadata.KeyProtectionType
import com.yubico.fido.metadata.MatcherProtectionType
import com.yubico.fido.metadata.UserVerificationMethod
import com.yubico.internal.util.JacksonCodecs
import org.junit.runner.RunWith
import org.scalatest.FunSpec
import org.scalatest.Matchers
import org.scalatestplus.junit.JUnitRunner
import org.scalatestplus.scalacheck.ScalaCheckDrivenPropertyChecks

import scala.util.Try

@RunWith(classOf[JUnitRunner])
class EnumsSpec
    extends FunSpec
    with Matchers
    with ScalaCheckDrivenPropertyChecks {

  val json = JacksonCodecs.json()

  describe("AttestationConveyancePreference") {
    describe("can be parsed from JSON") {
      it("but throws IllegalArgumentException for unknown values.") {
        val result = Try(
          json.readValue("\"foo\"", classOf[AttestationConveyancePreference])
        )
        result.failed.get.getCause shouldBe an[IllegalArgumentException]
      }
    }
  }

  describe("AuthenticatorAttachment") {
    describe("can be parsed from JSON") {
      it("but throws IllegalArgumentException for unknown values.") {
        val result = Try(
          json.readValue("\"foo\"", classOf[AuthenticatorAttachment])
        )
        result.failed.get.getCause shouldBe an[IllegalArgumentException]
      }
    }
  }

  describe("AuthenticatorTransport") {
    it("sorts in lexicographical order.") {
      val list = List(
        AuthenticatorTransport.USB,
        AuthenticatorTransport.BLE,
        AuthenticatorTransport.NFC,
        AuthenticatorTransport.INTERNAL,
      )
      list.sorted should equal(
        List(
          AuthenticatorTransport.BLE,
          AuthenticatorTransport.INTERNAL,
          AuthenticatorTransport.NFC,
          AuthenticatorTransport.USB,
        )
      )
    }
  }

  describe("COSEAlgorithmIdentifier") {
    describe("can be parsed from JSON") {
      it("but throws IllegalArgumentException for unknown values.") {
        val result = Try(
          json.readValue("1337", classOf[COSEAlgorithmIdentifier])
        )
        result.failed.get.getCause shouldBe an[IllegalArgumentException]
      }
    }
  }

  describe("PublicKeyCredentialType") {
    describe("can be parsed from JSON") {
      it("but throws IllegalArgumentException for unknown values.") {
        val result = Try(
          json.readValue("\"foo\"", classOf[PublicKeyCredentialType])
        )
        result.failed.get.getCause shouldBe an[IllegalArgumentException]
      }
    }
  }

  describe("ResidentKeyRequirement") {
    describe("can be parsed from JSON") {
      it("but throws IllegalArgumentException for unknown values.") {
        val result = Try(
          json.readValue("\"foo\"", classOf[ResidentKeyRequirement])
        )
        result.failed.get.getCause shouldBe an[IllegalArgumentException]
      }
    }
  }

  describe("UserVerificationRequirement") {
    describe("can be parsed from JSON") {
      it("but throws IllegalArgumentException for unknown values.") {
        val result = Try(
          json.readValue("\"foo\"", classOf[UserVerificationRequirement])
        )
        result.failed.get.getCause shouldBe an[IllegalArgumentException]
      }
    }
  }

  describe("FIDO") {
    describe("UserVerificationMethod") {
      it("can be parsed from a singleton bit field.") {
        UserVerificationMethod.fromValue(
          1
        ) should be theSameInstanceAs UserVerificationMethod.USER_VERIFY_PRESENCE_INTERNAL
        UserVerificationMethod.fromValue(
          2
        ) should be theSameInstanceAs UserVerificationMethod.USER_VERIFY_FINGERPRINT_INTERNAL
        UserVerificationMethod.fromValue(
          4
        ) should be theSameInstanceAs UserVerificationMethod.USER_VERIFY_PASSCODE_INTERNAL
        UserVerificationMethod.fromValue(
          8
        ) should be theSameInstanceAs UserVerificationMethod.USER_VERIFY_VOICEPRINT_INTERNAL
        UserVerificationMethod.fromValue(
          16
        ) should be theSameInstanceAs UserVerificationMethod.USER_VERIFY_FACEPRINT_INTERNAL
        UserVerificationMethod.fromValue(
          32
        ) should be theSameInstanceAs UserVerificationMethod.USER_VERIFY_LOCATION_INTERNAL
        UserVerificationMethod.fromValue(
          64
        ) should be theSameInstanceAs UserVerificationMethod.USER_VERIFY_EYEPRINT_INTERNAL
        UserVerificationMethod.fromValue(
          128
        ) should be theSameInstanceAs UserVerificationMethod.USER_VERIFY_PATTERN_INTERNAL
        UserVerificationMethod.fromValue(
          256
        ) should be theSameInstanceAs UserVerificationMethod.USER_VERIFY_HANDPRINT_INTERNAL
        UserVerificationMethod.fromValue(
          512
        ) should be theSameInstanceAs UserVerificationMethod.USER_VERIFY_NONE
        UserVerificationMethod.fromValue(
          1024
        ) should be theSameInstanceAs UserVerificationMethod.USER_VERIFY_ALL
      }

      it("does not accept unknown values.") {
        an[IllegalArgumentException] shouldBe thrownBy {
          UserVerificationMethod.fromValue(3)
        }
      }
    }

    describe("KeyProtectionType") {
      it("can be parsed from a singleton bit field.") {
        KeyProtectionType.fromValue(
          1
        ) should be theSameInstanceAs KeyProtectionType.KEY_PROTECTION_SOFTWARE
        KeyProtectionType.fromValue(
          2
        ) should be theSameInstanceAs KeyProtectionType.KEY_PROTECTION_HARDWARE
        KeyProtectionType.fromValue(
          4
        ) should be theSameInstanceAs KeyProtectionType.KEY_PROTECTION_TEE
        KeyProtectionType.fromValue(
          8
        ) should be theSameInstanceAs KeyProtectionType.KEY_PROTECTION_SECURE_ELEMENT
        KeyProtectionType.fromValue(
          16
        ) should be theSameInstanceAs KeyProtectionType.KEY_PROTECTION_REMOTE_HANDLE
      }

      it("does not accept unknown values.") {
        an[IllegalArgumentException] shouldBe thrownBy {
          KeyProtectionType.fromValue(3)
        }
      }
    }

    describe("MatcherProtectionType") {
      it("can be parsed from a singleton bit field.") {
        MatcherProtectionType.fromValue(
          1
        ) should be theSameInstanceAs MatcherProtectionType.MATCHER_PROTECTION_SOFTWARE
        MatcherProtectionType.fromValue(
          2
        ) should be theSameInstanceAs MatcherProtectionType.MATCHER_PROTECTION_TEE
        MatcherProtectionType.fromValue(
          4
        ) should be theSameInstanceAs MatcherProtectionType.MATCHER_PROTECTION_ON_CHIP
      }

      it("does not accept unknown values.") {
        an[IllegalArgumentException] shouldBe thrownBy {
          MatcherProtectionType.fromValue(3)
        }
      }
    }
  }

}
