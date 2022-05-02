package com.yubico.fido.metadata

import com.yubico.internal.util.JacksonCodecs
import com.yubico.webauthn.data.ByteArray
import org.scalatest.FunSpec
import org.scalatest.Matchers
import org.scalatestplus.scalacheck.ScalaCheckDrivenPropertyChecks

class MetadataBlobSpec
    extends FunSpec
    with Matchers
    with ScalaCheckDrivenPropertyChecks {

  describe("FIDO Metadata Service 3 blob payloads") {
    it("can be parsed as MetadataBLOBPayload.") {
      val blob = JacksonCodecs
        .json()
        .readValue(
          ByteArray
            .fromBase64Url(FidoMds3Examples.BlobPayloadBase64url)
            .getBytes,
          classOf[MetadataBLOBPayload],
        )
      blob should not be null
      blob.getLegalHeader should equal(
        "Retrieval and use of this BLOB indicates acceptance of the appropriate agreement located at https://fidoalliance.org/metadata/metadata-legal-terms/"
      )
    }

    it(
      "are structurally identical after multiple (de)serialization round-trips."
    ) {
      val json = JacksonCodecs.json()
      val blob1 = json
        .readValue(
          ByteArray
            .fromBase64Url(FidoMds3Examples.BlobPayloadBase64url)
            .getBytes,
          classOf[MetadataBLOBPayload],
        )
      val encodedBlob1 = json.writeValueAsBytes(blob1)
      val blob2 = json.readValue(encodedBlob1, classOf[MetadataBLOBPayload])
      val encodedBlob2 = json.writeValueAsBytes(blob2)
      val blob3 = json.readValue(encodedBlob2, classOf[MetadataBLOBPayload])

      blob2 should not be null
      blob2 should equal(blob1)
      blob3 should not be null
      blob3 should equal(blob1)
    }
  }

}
