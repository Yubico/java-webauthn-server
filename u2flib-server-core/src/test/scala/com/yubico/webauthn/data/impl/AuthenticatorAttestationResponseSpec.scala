package com.yubico.webauthn.data.impl

import com.fasterxml.jackson.databind.JsonNode
import com.yubico.webauthn.data.ArrayBuffer
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

  }

}
