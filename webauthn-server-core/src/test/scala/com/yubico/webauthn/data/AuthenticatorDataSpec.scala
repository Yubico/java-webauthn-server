package com.yubico.webauthn.data

import java.security.interfaces.ECPublicKey

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.JsonNode
import com.yubico.scala.util.JavaConverters._
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding
import com.yubico.webauthn.util.BinaryUtil
import com.yubico.webauthn.util.WebAuthnCodecs
import org.junit.runner.RunWith
import org.scalatest.FunSpec
import org.scalatest.Matchers
import org.scalatest.junit.JUnitRunner

@RunWith(classOf[JUnitRunner])
class AuthenticatorDataSpec extends FunSpec with Matchers {

  def parseJson(json: String): JsonNode = new ObjectMapper().readTree(json)

  describe("AuthenticatorData") {

    def generateTests(authDataHex: HexString, hasAttestation: Boolean = false, hasExtensions: Boolean = false): Unit = {

      val authData = AuthenticatorData(BinaryUtil.fromHex(authDataHex).get)

      it("gets the correct RP ID hash from the raw bytes.") {
        BinaryUtil.toHex(authData.rpIdHash) should equal("49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763")
      }

      it("gets the correct flags from the raw bytes.") {
        authData.flags.UP should be (true)
        authData.flags.UV should be (false)
        authData.flags.AT should equal (hasAttestation)
        authData.flags.ED should equal (hasExtensions)
      }

      it("gets the correct signature counter from the raw bytes.") {
        authData.signatureCounter should equal(1337)

        val evilBytes = BinaryUtil.fromHex("49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d976301ffffffff").get
        AuthenticatorData(evilBytes).signatureCounter should equal(0xffffffffL)
        AuthenticatorData(evilBytes).signatureCounter should be > Int.MaxValue.toLong
      }

      if (hasAttestation) {
        it("gets the correct attestation data from the raw bytes.") {
          authData.attestationData.asScala shouldBe defined
          BinaryUtil.toHex(authData.attestationData.get.aaguid) should equal ("00000000000000000000000000000000")
          BinaryUtil.toHex(authData.attestationData.get.credentialId) should equal ("00085b9bfacca2df2ad6efef962dd05190249b429cc35091785bd6f80e68cb2fee69a5c0796c2c20ca8e634a521481995cc6c6989d4f91f43151392bcaa486d8072e399094e9d2e14a7065a79b8f4bc9610043ab0bd3383c9c041a460c741db5b36e5c85e9727ee8b1803f335666abee049af72ee1bc18a9ee782404ad31f59eb332db488a2a779a3b4a17798cb1b4790e92edc99cde9edbb617e35f6135c7026ca5")

          val pubkey: ECPublicKey = authData.attestationData.get.parsedCredentialPublicKey
          pubkey.getAlgorithm should equal ("ES256")
          pubkey.getW.getAffineX.toByteArray should equal (U2fB64Encoding.decode("aoOddornU5isY2MWLBDqzR4rQ70aEjE9DCRBTSQOydw"))
          pubkey.getW.getAffineY.toByteArray should equal (U2fB64Encoding.decode("LW3Pt8GP0pOPbYjXOjvwjQ4x_X5xDKlV57nfKXZxU4E"))
        }
      }

      if (hasExtensions) {
        it("gets the correct extension data from the raw bytes.") {
          authData.extensions.asScala shouldBe defined
          authData.extensions.get should equal (parseJson("""{ "foo": "bar" }"""))
        }
      }
    }

    describe("with neither attestation data nor extensions") {
      generateTests("49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630100000539")
    }

    describe("with only attestation data") {
      generateTests(
        "49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d976341000005390000000000000000000000000000000000a200085b9bfacca2df2ad6efef962dd05190249b429cc35091785bd6f80e68cb2fee69a5c0796c2c20ca8e634a521481995cc6c6989d4f91f43151392bcaa486d8072e399094e9d2e14a7065a79b8f4bc9610043ab0bd3383c9c041a460c741db5b36e5c85e9727ee8b1803f335666abee049af72ee1bc18a9ee782404ad31f59eb332db488a2a779a3b4a17798cb1b4790e92edc99cde9edbb617e35f6135c7026ca5a363616c67654553323536617858206a839d768ae75398ac6363162c10eacd1e2b43bd1a12313d0c24414d240ec9dc617958202d6dcfb7c18fd2938f6d88d73a3bf08d0e31fd7e710ca955e7b9df2976715381",
        hasAttestation = true
      )
    }

    describe("with only extensions") {
      generateTests(
        "49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97638100000539a163666f6f63626172",
        hasExtensions = true
      )
    }

    describe("with both attestation data and extensions") {
      generateTests(
        "49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763c1000005390000000000000000000000000000000000a200085b9bfacca2df2ad6efef962dd05190249b429cc35091785bd6f80e68cb2fee69a5c0796c2c20ca8e634a521481995cc6c6989d4f91f43151392bcaa486d8072e399094e9d2e14a7065a79b8f4bc9610043ab0bd3383c9c041a460c741db5b36e5c85e9727ee8b1803f335666abee049af72ee1bc18a9ee782404ad31f59eb332db488a2a779a3b4a17798cb1b4790e92edc99cde9edbb617e35f6135c7026ca5a363616c67654553323536617858206a839d768ae75398ac6363162c10eacd1e2b43bd1a12313d0c24414d240ec9dc617958202d6dcfb7c18fd2938f6d88d73a3bf08d0e31fd7e710ca955e7b9df2976715381a163666f6f63626172",
        hasAttestation = true,
        hasExtensions = true
      )
    }

  }

}
