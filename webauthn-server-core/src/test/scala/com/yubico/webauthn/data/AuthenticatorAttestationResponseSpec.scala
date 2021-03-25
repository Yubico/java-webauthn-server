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

import org.junit.runner.RunWith
import org.scalatest.FunSpec
import org.scalatest.Matchers
import org.scalatestplus.junit.JUnitRunner

@RunWith(classOf[JUnitRunner])
class AuthenticatorAttestationResponseSpec extends FunSpec with Matchers {

  describe("AuthenticatorAttestationResponse") {

    val exampleAttestation =
      ByteArray.fromHex("a368617574684461746159012c49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d976341000000000000000000000000000000000000000000a20008dce8bdc3fc2c734a29a20ddb6509bceb721d7381859ab2548ae350fdb1962df68f1ebc08dbb5263c653b4e855b45b7df85b4926ed4572f2af78da28028143d6a6de8c0afcc6c6fbb648ce0bac022ba0a2303d2fced0d9772fcc0d32e281c8563082820e9bfd2e76241637ccbc36aebd85f398f6b6863d3d6755e398e05faf101e467c201219a83b2bf4269efc6e82f2c95dbfbc2a979ea2b78dea9b9fe467a2fa363616c6765455332353661785820c5df3292ce78ea68322b36073fd3b012a35cc9352cba7abd5ed2c287f6112b5361795820a83b6a518319bee86dccd1c8d54b3acb4f590e2cf7d26616aad3e7aa49fc8b4c63666d74686669646f2d7532666761747453746d74a26378356381590136308201323081d9a003020102020500a5427a1d300a06082a8648ce3d0403023021311f301d0603550403131646697265666f782055324620536f667420546f6b656e301e170d3137303833303134353130365a170d3137303930313134353130365a3021311f301d0603550403131646697265666f782055324620536f667420546f6b656e3059301306072a8648ce3d020106082a8648ce3d0301070342000409b9c8303e3a9f1cc0c4bb83c6d56a223699137387ad27dd01ad9c8e0c80addce10e52e622197576f756e38d5965bf98d53ece5af4b0ec003ad08f932bd84c1e300a06082a8648ce3d040302034800304502210083239a57e0fa99224b2c7989998cf833d5c1562df38d285d46cab1d6cf46ae9e02204cfd5deb11de1fdafc4e899f8d03388164beaff2e4263a82210ccc38906981236373696758463044022049c439848ec81672461cc0ea629f297cc7228450a6b0d08872ab969364ec6a6202200ea1acec627fd0e616d23da3e8bfa38a5527f2007cfe3fed63e5f3e2f7e25b11")

    val booExtension = "far"
    val challenge = ByteArray.fromBase64Url("HfpNmDkOp66Edjd5-uvwlg")
    val fooExtension = "bar"
    val origin = "localhost"
    val tokenBindingStatus = TokenBindingStatus.PRESENT
    val tokenBindingId = ByteArray.fromBase64Url("IgqNmDkOp68Edjd8-uwxmh")
    val exampleJson: ByteArray =
      new ByteArray(s"""{
          "authenticatorExtensions":{"boo":"${booExtension}"},
          "challenge":"${challenge.getBase64Url}",
          "clientExtensions":{"foo":"${fooExtension}"},
          "origin":"${origin}",
          "tokenBinding":{"status":"${tokenBindingStatus.toJsonString}","id":"${tokenBindingId.getBase64Url}"},
          "type":"webauthn.get"
        }""".getBytes("UTF-8"))

    describe("has a clientDataJSON field which") {

      it("can be parsed as JSON.") {
        val clientData = AuthenticatorAttestationResponse
          .builder()
          .attestationObject(exampleAttestation)
          .clientDataJSON(exampleJson)
          .build()
          .getClientData
        clientData.getChallenge should equal(challenge)
      }

      describe("defines attributes on the contained CollectedClientData:") {
        val response = AuthenticatorAttestationResponse
          .builder()
          .attestationObject(exampleAttestation)
          .clientDataJSON(exampleJson)
          .build()

        it("challenge") {
          response.getClientData.getChallenge should equal(challenge)
        }

        it("origin") {
          response.getClientData.getOrigin should equal(origin)
        }

        describe("tokenBinding") {
          it("status") {
            response.getClientData.getTokenBinding.get.getStatus should equal(
              tokenBindingStatus
            )
          }

          it("id") {
            response.getClientData.getTokenBinding.get.getId.get should equal(
              tokenBindingId
            )
          }
        }

      }

    }

    it("can decode its attestationObject as CBOR.") {
      val response = AuthenticatorAttestationResponse
        .builder()
        .attestationObject(exampleAttestation)
        .clientDataJSON(exampleJson)
        .build()

      response.getAttestation.getFormat should be("fido-u2f")
    }

  }

}
