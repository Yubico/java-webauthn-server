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

      val challenge = "HfpNmDkOp66Edjd5-uvwlg"
      val exampleJson: ArrayBuffer = Vector(s"""{"challenge":"${challenge}","hashAlg":"SHA-256","origin":"localhost"}""".getBytes("UTF-8") :_*)

      it("can be parsed as JSON.") {
        val clientData: JsonNode = new AuthenticatorAttestationResponse(null, exampleJson).clientData

        clientData.isObject should be (true)
        clientData.asInstanceOf[JsonNode].get("challenge").asText should equal (challenge)
      }

    }

  }

}
