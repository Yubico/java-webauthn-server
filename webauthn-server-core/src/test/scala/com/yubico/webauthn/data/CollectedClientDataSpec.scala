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

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.node.ObjectNode
import com.yubico.internal.util.JacksonCodecs
import org.junit.runner.RunWith
import org.scalatest.FunSpec
import org.scalatest.Matchers
import org.scalatestplus.junit.JUnitRunner

@RunWith(classOf[JUnitRunner])
class CollectedClientDataSpec extends FunSpec with Matchers {

  def parse(json: JsonNode): CollectedClientData =
    new CollectedClientData(
      new ByteArray(JacksonCodecs.json().writeValueAsBytes(json))
    )

  describe("CollectedClientData") {

    val defaultJson: ObjectNode = JacksonCodecs.json
      .readTree("""{
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
      }""")
      .asInstanceOf[ObjectNode]

    it("can be parsed from JSON.") {
      val cd = parse(defaultJson)

      cd.getChallenge.getBase64Url should equal("aaaa")
      cd.getOrigin should equal("example.org")
      cd.getType should equal("webauthn.create")
      cd.getTokenBinding.get should equal(
        TokenBindingInfo.present(ByteArray.fromBase64Url("bbbb"))
      )
    }

    describe("forbids null value for") {
      it("field: challenge") {
        an[IllegalArgumentException] should be thrownBy parse(
          defaultJson.set("challenge", defaultJson.nullNode())
        )
        an[IllegalArgumentException] should be thrownBy parse(
          defaultJson.remove("challenge")
        )
      }

      it("field: origin") {
        an[IllegalArgumentException] should be thrownBy parse(
          defaultJson.set("origin", defaultJson.nullNode())
        )
        an[IllegalArgumentException] should be thrownBy parse(
          defaultJson.remove("origin")
        )
      }

      it("field: type") {
        an[IllegalArgumentException] should be thrownBy parse(
          defaultJson.set("type", defaultJson.nullNode())
        )
        an[IllegalArgumentException] should be thrownBy parse(
          defaultJson.remove("type")
        )
      }
    }
  }

}
