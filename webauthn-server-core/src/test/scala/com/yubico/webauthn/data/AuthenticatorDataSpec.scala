package com.yubico.webauthn.data

import com.upokecenter.cbor.CBORObject
import com.yubico.scala.util.JavaConverters._
import com.yubico.util.ByteArray
import com.yubico.webauthn.impl.util.WebAuthnCodecs
import org.junit.runner.RunWith
import org.scalatest.FunSpec
import org.scalatest.Matchers
import org.scalatest.junit.JUnitRunner

import scala.util.Try
import scala.util.Failure

@RunWith(classOf[JUnitRunner])
class AuthenticatorDataSpec extends FunSpec with Matchers {

  def jsonToCbor(json: String): ArrayBuffer = CBORObject.FromJSONString(json).EncodeToBytes.toVector

  describe("AuthenticatorData") {

    def generateTests(authDataHex: HexString, hasAttestation: Boolean = false, hasExtensions: Boolean = false): Unit = {

      val authData = new AuthenticatorData(ByteArray.fromHex(authDataHex))

      it("gets the correct RP ID hash from the raw bytes.") {
        authData.getRpIdHash.getHex should equal("49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763")
      }

      it("gets the correct flags from the raw bytes.") {
        authData.getFlags.UP should be (true)
        authData.getFlags.UV should be (false)
        authData.getFlags.AT should equal (hasAttestation)
        authData.getFlags.ED should equal (hasExtensions)
      }

      it("gets the correct signature counter from the raw bytes.") {
        authData.getSignatureCounter should equal(1337)

        val evilBytes = ByteArray.fromHex("49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d976301ffffffff")
        new AuthenticatorData(evilBytes).getSignatureCounter should equal(0xffffffffL)
        new AuthenticatorData(evilBytes).getSignatureCounter should be > Int.MaxValue.toLong
      }

      if (hasAttestation) {
        it("gets the correct attestation data from the raw bytes.") {
          authData.getAttestationData.asScala shouldBe defined
          authData.getAttestationData.get.getAaguid.getHex should equal ("000102030405060708090a0b0c0d0e0f")
          authData.getAttestationData.get.getCredentialId.getHex should equal ("7137c4e57894dce742723f9966c1e71c7c966f14e9429d5b2a2098a68416deec")

          val pubkey: ByteArray = WebAuthnCodecs.ecPublicKeyToRaw(authData.getAttestationData.get.getParsedCredentialPublicKey)
          pubkey should equal (ByteArray.fromHex("04DAFE0DE5312BA080A5CCDF6B483B10EF19A2454D1E17A8350311A0B7FF0566EF8EC6324D2C81398D2E80BC985B910B26970A0F408C9DE19BECCF39899A41674D"))
        }
      }

      if (hasExtensions) {
        it("gets the correct extension data from the raw bytes.") {
          authData.getExtensions.asScala shouldBe defined
          authData.getExtensions.get.EncodeToBytes().toVector should equal (jsonToCbor("""{ "foo": "bar" }"""))
        }
      }
    }

    describe("with neither attestation data nor extensions") {
      generateTests(
        "49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763" // RP ID hash
        + "01" // Flags
        + "00000539" // Signature count
      )
    }

    describe("with only attestation data") {
      generateTests(
        "49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763" // RP ID hash
        + "41" // Flags
        + "00000539" // Signature count
        + "000102030405060708090a0b0c0d0e0f" // AAGUID
        + "0020" // Credential ID length
        + "7137c4e57894dce742723f9966c1e71c7c966f14e9429d5b2a2098a68416deec" // Credential ID
        + "a52258208ec6324d2c81398d2e80bc985b910b26970a0f408c9de19beccf39899a41674d03260102215820dafe0de5312ba080a5ccdf6b483b10ef19a2454d1e17a8350311a0b7ff0566ef2001" // Credential public key COSE_key
        ,
        hasAttestation = true
      )

    }

    describe("with only extensions") {
      generateTests(
        "49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763" // RP ID hash
        + "81" // Flags
        + "00000539" // Signature count
        + "a163666f6f63626172" // Extensions
        ,
        hasExtensions = true
      )
    }

    describe("with both attestation data and extensions") {
      generateTests(
        "49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763" // RP ID hash
          + "c1" // Flags
          + "00000539" // Signature count
          + "000102030405060708090a0b0c0d0e0f" // AAGUID
          + "0020" // Credential ID length
          + "7137c4e57894dce742723f9966c1e71c7c966f14e9429d5b2a2098a68416deec" // Credential ID
          + "a52258208ec6324d2c81398d2e80bc985b910b26970a0f408c9de19beccf39899a41674d03260102215820dafe0de5312ba080a5ccdf6b483b10ef19a2454d1e17a8350311a0b7ff0566ef2001" // Credential public key COSE_key
          + "a163666f6f63626172" // Extensions
        ,
        hasAttestation = true,
        hasExtensions = true
      )
    }

    describe("rejects a byte array with both attestation data and extensions if") {
      def authDataBytes(flags: String): ByteArray =
        ByteArray.fromHex(
          "49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763" // RP ID hash
          + flags
          + "00000539" // Signature count
          + "000102030405060708090a0b0c0d0e0f" // AAGUID
          + "0020" // Credential ID length
          + "7137c4e57894dce742723f9966c1e71c7c966f14e9429d5b2a2098a68416deec" // Credential ID
          + "a52258208ec6324d2c81398d2e80bc985b910b26970a0f408c9de19beccf39899a41674d03260102215820dafe0de5312ba080a5ccdf6b483b10ef19a2454d1e17a8350311a0b7ff0566ef2001" // Credential public key COSE_key
          + "a163666f6f63626172" // Extensions
        )

      it("flags indicate only attestation data") {
        val authData = Try(new AuthenticatorData(authDataBytes("41")))

        authData shouldBe a [Failure[_]]
        authData.failed.get shouldBe an [IllegalArgumentException]
      }

      it("flags indicate only extensions") {
        val authData = Try(new AuthenticatorData(authDataBytes("81")))

        authData shouldBe a [Failure[_]]
        authData.failed.get shouldBe an [IllegalArgumentException]
      }
    }

  }

}
