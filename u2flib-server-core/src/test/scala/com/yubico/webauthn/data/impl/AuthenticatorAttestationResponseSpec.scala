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

    it("can decode its attestationObject as CBOR.") {
      val exampleAttestation = BinaryUtil.fromHex("a368617574684461746159012c49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d976341000000000000000000000000000000000000000000a20008dce8bdc3fc2c734a29a20ddb6509bceb721d7381859ab2548ae350fdb1962df68f1ebc08dbb5263c653b4e855b45b7df85b4926ed4572f2af78da28028143d6a6de8c0afcc6c6fbb648ce0bac022ba0a2303d2fced0d9772fcc0d32e281c8563082820e9bfd2e76241637ccbc36aebd85f398f6b6863d3d6755e398e05faf101e467c201219a83b2bf4269efc6e82f2c95dbfbc2a979ea2b78dea9b9fe467a2fa363616c6765455332353661785820c5df3292ce78ea68322b36073fd3b012a35cc9352cba7abd5ed2c287f6112b5361795820a83b6a518319bee86dccd1c8d54b3acb4f590e2cf7d26616aad3e7aa49fc8b4c63666d74686669646f2d7532666761747453746d74a26378356381590136308201323081d9a003020102020500a5427a1d300a06082a8648ce3d0403023021311f301d0603550403131646697265666f782055324620536f667420546f6b656e301e170d3137303833303134353130365a170d3137303930313134353130365a3021311f301d0603550403131646697265666f782055324620536f667420546f6b656e3059301306072a8648ce3d020106082a8648ce3d0301070342000409b9c8303e3a9f1cc0c4bb83c6d56a223699137387ad27dd01ad9c8e0c80addce10e52e622197576f756e38d5965bf98d53ece5af4b0ec003ad08f932bd84c1e300a06082a8648ce3d040302034800304502210083239a57e0fa99224b2c7989998cf833d5c1562df38d285d46cab1d6cf46ae9e02204cfd5deb11de1fdafc4e899f8d03388164beaff2e4263a82210ccc38906981236373696758463044022049c439848ec81672461cc0ea629f297cc7228450a6b0d08872ab969364ec6a6202200ea1acec627fd0e616d23da3e8bfa38a5527f2007cfe3fed63e5f3e2f7e25b11").get
      val response = AuthenticatorAttestationResponse(exampleAttestation, null)

      response.attestation.format should be ("fido-u2f")
    }

  }

}
