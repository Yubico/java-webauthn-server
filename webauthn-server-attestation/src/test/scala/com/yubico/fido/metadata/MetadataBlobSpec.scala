package com.yubico.fido.metadata

import com.yubico.fido.metadata.Generators.arbitrarySupportedCtapOptions
import com.yubico.internal.util.JacksonCodecs
import com.yubico.webauthn.data.ByteArray
import org.scalacheck.Arbitrary
import org.scalacheck.Gen
import org.scalatest.funspec.AnyFunSpec
import org.scalatest.matchers.should.Matchers
import org.scalatestplus.scalacheck.ScalaCheckDrivenPropertyChecks

import scala.jdk.CollectionConverters.SetHasAsScala
import scala.jdk.OptionConverters.RichOptional

class MetadataBlobSpec
    extends AnyFunSpec
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

  describe("SupportedCtapOptions") {
    it("can be parsed from an empty JSON object.") {
      val options = JacksonCodecs
        .json()
        .readValue("{}", classOf[SupportedCtapOptions])
      options should not be null
      options.isPlat should be(false)
      options.isRk should be(false)
      options.isUp should be(false)
      options.isUv should be(false)
      options.isPinUvAuthToken should be(false)
      options.isNoMcGaPermissionsWithClientPin should be(false)
      options.isLargeBlobs should be(false)
      options.isEp should be(false)
      options.isBioEnroll should be(false)
      options.isUserVerificationMgmtPreview should be(false)
      options.isUvBioEnroll should be(false)
      options.isAuthnrCfg should be(false)
      options.isUvAcfg should be(false)
      options.isCredMgmt should be(false)
      options.isCredentialMgmtPreview should be(false)
      options.isSetMinPINLength should be(false)
      options.isMakeCredUvNotRqd should be(false)
      options.isAlwaysUv should be(false)
    }

    it(
      "are structurally identical after multiple (de)serialization round-trips."
    ) {
      val json = JacksonCodecs.json()
      val blob = json
        .readValue(
          ByteArray
            .fromBase64Url(FidoMds3Examples.BlobPayloadBase64url)
            .getBytes,
          classOf[MetadataBLOBPayload],
        )
      val blobOptions = blob.getEntries.asScala
        .flatMap(entry => entry.getMetadataStatement.toScala)
        .flatMap(statement => statement.getAuthenticatorGetInfo.toScala)
        .flatMap(info => info.getOptions.toScala)
      forAll(Gen.oneOf(Arbitrary.arbitrary, Gen.oneOf(blobOptions))) {
        (options1: SupportedCtapOptions) =>
          val encoded1 = json.writeValueAsBytes(options1)
          val options2 = json.readValue(encoded1, classOf[SupportedCtapOptions])
          val encoded2 = json.writeValueAsBytes(options2)
          val options3 = json.readValue(encoded2, classOf[SupportedCtapOptions])

          options2 should not be null
          options2 should equal(options1)
          options3 should not be null
          options3 should equal(options1)
      }
    }
  }
}
