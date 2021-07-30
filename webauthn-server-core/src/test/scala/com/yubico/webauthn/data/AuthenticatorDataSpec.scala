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

import com.upokecenter.cbor.CBORObject
import com.yubico.internal.util.BinaryUtil
import com.yubico.internal.util.scala.JavaConverters._
import com.yubico.webauthn.WebAuthnTestCodecs
import com.yubico.webauthn.data.Generators.byteArray
import org.junit.runner.RunWith
import org.scalacheck.Arbitrary.arbitrary
import org.scalacheck.Gen
import org.scalatest.FunSpec
import org.scalatest.Matchers
import org.scalatestplus.junit.JUnitRunner
import org.scalatestplus.scalacheck.ScalaCheckDrivenPropertyChecks

import java.security.interfaces.ECPublicKey
import scala.util.Failure
import scala.util.Try

@RunWith(classOf[JUnitRunner])
class AuthenticatorDataSpec
    extends FunSpec
    with Matchers
    with ScalaCheckDrivenPropertyChecks {

  def jsonToCbor(json: String): ByteArray =
    new ByteArray(CBORObject.FromJSONString(json).EncodeToBytes)

  describe("AuthenticatorData") {

    it("must be at least 37 bytes.") {
      forAll(byteArray(36)) { authData =>
        an[IllegalArgumentException] shouldBe thrownBy {
          new AuthenticatorData(authData)
        }
      }
    }

    it("with attested credential data must be at least 55 bytes.") {
      forAll(byteArray(37, 54)) { bytes =>
        val authData = new ByteArray(
          bytes.getBytes.updated(32, (bytes.getBytes.apply(32) | 0x40).toByte)
        )
        val result = Try(new AuthenticatorData(authData))
        result shouldBe a[Failure[_]]
        result.failed.get.getMessage should include(
          "Attested credential data must contain at least"
        )
      }
    }

    it("with attested credential data must be at least long enough to accommodate the credential ID.") {
      forAll(for {
        prefix <- Gen.infiniteLazyList(arbitrary[Byte]).map(_.take(53).toArray)
        credIdLen <- Gen.chooseNum(1, 2048)
        credId <- Gen.listOfN(credIdLen - 1, arbitrary[Byte])
      } yield (prefix, credIdLen, credId)) {
        case (prefix, credIdLen, credId) =>
          val bytes = prefix ++ BinaryUtil.encodeUint16(credIdLen) ++ credId
          val authData =
            new ByteArray(bytes.updated(32, (bytes(32) | 0x40).toByte))
          val result = Try(new AuthenticatorData(authData))
          result shouldBe a[Failure[_]]
          result.failed.get.getMessage should include(
            "Expected credential ID of length"
          )
      }
    }

    def generateTests(
        authDataHex: String,
        hasAttestation: Boolean = false,
        hasExtensions: Boolean = false,
    ): Unit = {

      val authData = new AuthenticatorData(ByteArray.fromHex(authDataHex))

      it("gets the correct RP ID hash from the raw bytes.") {
        authData.getRpIdHash.getHex should equal(
          "49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763"
        )
      }

      it("gets the correct flags from the raw bytes.") {
        authData.getFlags.UP should be(true)
        authData.getFlags.UV should be(false)
        authData.getFlags.AT should equal(hasAttestation)
        authData.getFlags.ED should equal(hasExtensions)
      }

      it("gets the correct signature counter from the raw bytes.") {
        authData.getSignatureCounter should equal(1337)

        val evilBytes =
          ByteArray.fromHex("49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d976301ffffffff")
        new AuthenticatorData(evilBytes).getSignatureCounter should equal(
          0xffffffffL
        )
        new AuthenticatorData(
          evilBytes
        ).getSignatureCounter should be > Int.MaxValue.toLong
      }

      if (hasAttestation) {
        it("gets the correct attestation data from the raw bytes.") {
          authData.getAttestedCredentialData.asScala shouldBe defined
          authData.getAttestedCredentialData.get.getAaguid.getHex should equal(
            "000102030405060708090a0b0c0d0e0f"
          )
          authData.getAttestedCredentialData.get.getCredentialId.getHex should equal(
            "7137c4e57894dce742723f9966c1e71c7c966f14e9429d5b2a2098a68416deec"
          )

          val pubkey: ByteArray = WebAuthnTestCodecs.ecPublicKeyToRaw(
            WebAuthnTestCodecs
              .importCosePublicKey(
                authData.getAttestedCredentialData.get.getCredentialPublicKey
              )
              .asInstanceOf[ECPublicKey]
          )
          pubkey should equal(
            ByteArray.fromHex("04DAFE0DE5312BA080A5CCDF6B483B10EF19A2454D1E17A8350311A0B7FF0566EF8EC6324D2C81398D2E80BC985B910B26970A0F408C9DE19BECCF39899A41674D")
          )
        }
      }

      if (hasExtensions) {
        it("gets the correct extension data from the raw bytes.") {
          authData.getExtensions.asScala shouldBe defined
          new ByteArray(
            authData.getExtensions.get.EncodeToBytes()
          ) should equal(jsonToCbor("""{ "foo": "bar" }"""))
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
        hasAttestation = true,
      )

    }

    describe("with only extensions") {
      generateTests(
        "49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763" // RP ID hash
          + "81" // Flags
          + "00000539" // Signature count
          + "a163666f6f63626172" // Extensions
        ,
        hasExtensions = true,
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
        hasExtensions = true,
      )
    }

    describe(
      "rejects a byte array with both attestation data and extensions if"
    ) {
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

        authData shouldBe a[Failure[_]]
        authData.failed.get shouldBe an[IllegalArgumentException]
      }

      it("flags indicate only extensions") {
        val authData = Try(new AuthenticatorData(authDataBytes("81")))

        authData shouldBe a[Failure[_]]
        authData.failed.get shouldBe an[IllegalArgumentException]
      }
    }

  }

}
