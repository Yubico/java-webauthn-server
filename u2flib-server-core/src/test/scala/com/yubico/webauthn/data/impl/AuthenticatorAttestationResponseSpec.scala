package com.yubico.webauthn.data.impl

import com.fasterxml.jackson.databind.JsonNode
import com.yubico.webauthn.data.ArrayBuffer
import com.yubico.webauthn.util.BinaryUtil
import org.junit.runner.RunWith
import org.scalatest.Matchers
import org.scalatest.FunSpec
import org.scalatest.junit.JUnitRunner


@RunWith(classOf[JUnitRunner])
class AuthenticatorAttestationResponseSpec extends FunSpec with Matchers {

  describe("AuthenticatorAttestationResponse") {

    describe("has a clientDataJSON field which") {

      val booExtension = "far"
      val challenge = "HfpNmDkOp66Edjd5-uvwlg"
      val fooExtension = "bar"
      val hashAlgorithm = "SHA-256"
      val origin = "localhost"
      val tokenBindingId = "IgqNmDkOp68Edjd8-uwxmh"
      val exampleJson: ArrayBuffer = Vector(s"""{"authenticatorExtensions":{"boo":"${booExtension}"},"challenge":"${challenge}","clientExtensions":{"foo":"${fooExtension}"},"hashAlgorithm":"${hashAlgorithm}","origin":"${origin}","tokenBindingId":"${tokenBindingId}"}""".getBytes("UTF-8") :_*)

      it("can be parsed as JSON.") {
        val clientData: JsonNode = AuthenticatorAttestationResponse(null, exampleJson).clientData

        clientData.isObject should be (true)
        clientData.asInstanceOf[JsonNode].get("challenge").asText should equal (challenge)
      }

      describe("defines attributes on the contained CollectedClientData:") {
        val response = AuthenticatorAttestationResponse(null, exampleJson)

        it("authenticatorExtensions") {
          response.collectedClientData.authenticatorExtensions.get.get("boo").asText should equal (booExtension)
        }

        it("challenge") {
          response.collectedClientData.challenge should equal (challenge)
        }

        it("clientExtensions") {
          response.collectedClientData.clientExtensions.get.get("foo").asText should equal (fooExtension)
        }

        it("hashAlgorithm") {
          response.collectedClientData.hashAlgorithm should equal (hashAlgorithm)
        }

        it("origin") {
          response.collectedClientData.origin should equal (origin)
        }

        it("tokenBindingId") {
          response.collectedClientData.tokenBindingId.get should equal (tokenBindingId)
        }

      }

    }

    describe("can compute the hash of its clientDataJSON if the named hashAlgorithm is") {
      def response(hashAlgorithm: String): AuthenticatorAttestationResponse = {
        val exampleJson: ArrayBuffer = Vector(s"""{"challenge":"HfpNmDkOp66Edjd5-uvwlg","hashAlgorithm":"${hashAlgorithm}","origin":"localhost"}""".getBytes("UTF-8"): _*)
        AuthenticatorAttestationResponse(null, exampleJson)
      }

      it("SHA-1.") {
        BinaryUtil.toHex(response("SHA-1").clientDataHash) should equal("3945cc878170e5271511dea9433a56c7d71e7689")
      }

      it("SHA-256.") {
        BinaryUtil.toHex(response("SHA-256").clientDataHash) should equal("ef320e07efe2040cdb716988f9146e186eadd383bde7c889702c5950c1b98ffb")
      }

      it("SHA-512.") {
        BinaryUtil.toHex(response("SHA-512").clientDataHash) should equal("7788211eb8daf4f647f76b329dd69f037f05b9b145a266184588d987dc06a1d55b693756e0667f924d312385284ae2b7d28a2556ba21a3087858f50d9eb21dcf")
      }
    }

  }

}
