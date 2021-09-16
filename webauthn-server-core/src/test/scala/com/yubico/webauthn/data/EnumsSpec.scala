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
        UserVerificationMethod.of(
          1
        ) should be theSameInstanceAs UserVerificationMethod.USER_VERIFY_PRESENCE
        UserVerificationMethod.of(
          2
        ) should be theSameInstanceAs UserVerificationMethod.USER_VERIFY_FINGERPRINT
        UserVerificationMethod.of(
          4
        ) should be theSameInstanceAs UserVerificationMethod.USER_VERIFY_PASSCODE
        UserVerificationMethod.of(
          8
        ) should be theSameInstanceAs UserVerificationMethod.USER_VERIFY_VOICEPRINT
        UserVerificationMethod.of(
          16
        ) should be theSameInstanceAs UserVerificationMethod.USER_VERIFY_FACEPRINT
        UserVerificationMethod.of(
          32
        ) should be theSameInstanceAs UserVerificationMethod.USER_VERIFY_LOCATION
        UserVerificationMethod.of(
          64
        ) should be theSameInstanceAs UserVerificationMethod.USER_VERIFY_EYEPRINT
        UserVerificationMethod.of(
          128
        ) should be theSameInstanceAs UserVerificationMethod.USER_VERIFY_PATTERN
        UserVerificationMethod.of(
          256
        ) should be theSameInstanceAs UserVerificationMethod.USER_VERIFY_HANDPRINT
        UserVerificationMethod.of(
          512
        ) should be theSameInstanceAs UserVerificationMethod.USER_VERIFY_NONE
        UserVerificationMethod.of(
          1024
        ) should be theSameInstanceAs UserVerificationMethod.USER_VERIFY_ALL
      }

      it("accepts unknown values.") {
        UserVerificationMethod.of(3) should not be null
        UserVerificationMethod
          .values() should not contain UserVerificationMethod.of(3)
      }

      it("toString() returns the full name of the constant.") {
        UserVerificationMethod.USER_VERIFY_PRESENCE.toString should equal(
          "USER_VERIFY_PRESENCE"
        )
        UserVerificationMethod.USER_VERIFY_FINGERPRINT.toString should equal(
          "USER_VERIFY_FINGERPRINT"
        )
        UserVerificationMethod.USER_VERIFY_PASSCODE.toString should equal(
          "USER_VERIFY_PASSCODE"
        )
        UserVerificationMethod.USER_VERIFY_VOICEPRINT.toString should equal(
          "USER_VERIFY_VOICEPRINT"
        )
        UserVerificationMethod.USER_VERIFY_FACEPRINT.toString should equal(
          "USER_VERIFY_FACEPRINT"
        )
        UserVerificationMethod.USER_VERIFY_LOCATION.toString should equal(
          "USER_VERIFY_LOCATION"
        )
        UserVerificationMethod.USER_VERIFY_EYEPRINT.toString should equal(
          "USER_VERIFY_EYEPRINT"
        )
        UserVerificationMethod.USER_VERIFY_PATTERN.toString should equal(
          "USER_VERIFY_PATTERN"
        )
        UserVerificationMethod.USER_VERIFY_HANDPRINT.toString should equal(
          "USER_VERIFY_HANDPRINT"
        )
        UserVerificationMethod.USER_VERIFY_NONE.toString should equal(
          "USER_VERIFY_NONE"
        )
        UserVerificationMethod.USER_VERIFY_ALL.toString should equal(
          "USER_VERIFY_ALL"
        )

        UserVerificationMethod.of(3).toString should startWith(
          "UserVerificationMethod("
        )
      }
    }

    describe("KeyProtectionType") {
      it("can be parsed from a singleton bit field.") {
        KeyProtectionType.of(
          1
        ) should be theSameInstanceAs KeyProtectionType.KEY_PROTECTION_SOFTWARE
        KeyProtectionType.of(
          2
        ) should be theSameInstanceAs KeyProtectionType.KEY_PROTECTION_HARDWARE
        KeyProtectionType.of(
          4
        ) should be theSameInstanceAs KeyProtectionType.KEY_PROTECTION_TEE
        KeyProtectionType.of(
          8
        ) should be theSameInstanceAs KeyProtectionType.KEY_PROTECTION_SECURE_ELEMENT
        KeyProtectionType.of(
          16
        ) should be theSameInstanceAs KeyProtectionType.KEY_PROTECTION_REMOTE_HANDLE
      }

      it("accepts unknown values.") {
        KeyProtectionType.of(3) should not be null
        KeyProtectionType.values() should not contain KeyProtectionType.of(3)
      }

      it("toString() returns the full name of the constant.") {
        KeyProtectionType.KEY_PROTECTION_SOFTWARE.toString should equal(
          "KEY_PROTECTION_SOFTWARE"
        )
        KeyProtectionType.KEY_PROTECTION_HARDWARE.toString should equal(
          "KEY_PROTECTION_HARDWARE"
        )
        KeyProtectionType.KEY_PROTECTION_TEE.toString should equal(
          "KEY_PROTECTION_TEE"
        )
        KeyProtectionType.KEY_PROTECTION_SECURE_ELEMENT.toString should equal(
          "KEY_PROTECTION_SECURE_ELEMENT"
        )
        KeyProtectionType.KEY_PROTECTION_REMOTE_HANDLE.toString should equal(
          "KEY_PROTECTION_REMOTE_HANDLE"
        )

        KeyProtectionType.of(3).toString should startWith("KeyProtectionType(")
      }
    }

    describe("MatcherProtectionType") {
      it("can be parsed from a singleton bit field.") {
        MatcherProtectionType.of(
          1
        ) should be theSameInstanceAs MatcherProtectionType.MATCHER_PROTECTION_SOFTWARE
        MatcherProtectionType.of(
          2
        ) should be theSameInstanceAs MatcherProtectionType.MATCHER_PROTECTION_TEE
        MatcherProtectionType.of(
          4
        ) should be theSameInstanceAs MatcherProtectionType.MATCHER_PROTECTION_ON_CHIP
      }

      it("accepts unknown values.") {
        MatcherProtectionType.of(3) should not be null
        MatcherProtectionType.values() should not contain MatcherProtectionType
          .of(3)
      }

      it("toString() returns the full name of the constant.") {
        MatcherProtectionType.MATCHER_PROTECTION_SOFTWARE.toString should equal(
          "MATCHER_PROTECTION_SOFTWARE"
        )
        MatcherProtectionType.MATCHER_PROTECTION_TEE.toString should equal(
          "MATCHER_PROTECTION_TEE"
        )
        MatcherProtectionType.MATCHER_PROTECTION_ON_CHIP.toString should equal(
          "MATCHER_PROTECTION_ON_CHIP"
        )

        MatcherProtectionType.of(3).toString should startWith(
          "MatcherProtectionType("
        )
      }
    }
  }

}
