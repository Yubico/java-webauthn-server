package com.yubico.webauthn.data

import com.fasterxml.jackson.databind.node.ObjectNode
import com.yubico.util.ByteArray
import com.yubico.webauthn.impl.util.WebAuthnCodecs
import org.junit.runner.RunWith
import org.scalatest.FunSpec
import org.scalatest.Matchers
import org.scalatest.junit.JUnitRunner


@RunWith(classOf[JUnitRunner])
class CollectedClientDataSpec extends FunSpec with Matchers {

  describe("CollectedClientData") {

    val defaultJson: ObjectNode = WebAuthnCodecs.json.readTree("""{
        "challenge": "aaaa",
        "origin": "example.org",
        "type": "webauthn.create",
        "authenticatorExtensions": {
          "foo": "bar"
        },
        "clientExtensions": {
          "boo": "far"
        },
        "tokenBinding": {
          "status": "present",
          "id": "bbbb"
        }
      }""").asInstanceOf[ObjectNode]

    it("can be parsed from JSON.") {
      val cd = new CollectedClientData(defaultJson)

      cd.getChallenge.getBase64Url should equal ("aaaa")
      cd.getOrigin should equal ("example.org")
      cd.getType should equal ("webauthn.create")
      cd.getAuthenticatorExtensions.get.size should equal (1)
      cd.getAuthenticatorExtensions.get.get("foo").textValue() should equal ("bar")
      cd.getClientExtensions.get.size should equal (1)
      cd.getClientExtensions.get.get("boo").textValue() should equal ("far")
      cd.getTokenBinding.get should equal (TokenBindingInfo.present(ByteArray.fromBase64Url("bbbb")))
    }


    describe("forbids null value for") {
      it("field: challenge") {
        an [IllegalArgumentException] should be thrownBy new CollectedClientData(defaultJson.set("challenge", defaultJson.nullNode()))
        an [IllegalArgumentException] should be thrownBy new CollectedClientData(defaultJson.remove("challenge"))
      }

      it("field: origin") {
        an [IllegalArgumentException] should be thrownBy new CollectedClientData(defaultJson.set("origin", defaultJson.nullNode()))
        an [IllegalArgumentException] should be thrownBy new CollectedClientData(defaultJson.remove("origin"))
      }

      it("field: type") {
        an [IllegalArgumentException] should be thrownBy new CollectedClientData(defaultJson.set("type", defaultJson.nullNode()))
        an [IllegalArgumentException] should be thrownBy new CollectedClientData(defaultJson.remove("type"))
      }
    }
  }

}
