package com.yubico.fido.metadata

import org.junit.runner.RunWith
import org.scalatest.BeforeAndAfter
import org.scalatest.funspec.AnyFunSpec
import org.scalatest.matchers.should.Matchers
import org.scalatest.tags.Network
import org.scalatest.tags.Slow
import org.scalatestplus.junit.JUnitRunner

import java.util.Optional
import scala.util.Success
import scala.util.Try

@Slow
@Network
@RunWith(classOf[JUnitRunner])
class FidoMetadataDownloaderIntegrationTest
    extends AnyFunSpec
    with Matchers
    with BeforeAndAfter {

  describe("FidoMetadataDownloader with default settings") {
    val downloader =
      FidoMetadataDownloader
        .builder()
        .expectLegalHeader(
          "Retrieval and use of this BLOB indicates acceptance of the appropriate agreement located at https://fidoalliance.org/metadata/metadata-legal-terms/"
        )
        .useDefaultTrustRoot()
        .useTrustRootCache(() => Optional.empty(), _ => {})
        .useDefaultBlob()
        .useBlobCache(() => Optional.empty(), _ => {})
        .build()

    it("downloads and verifies the root cert and BLOB successfully.") {
      // This test requires the system property com.sun.security.enableCRLDP=true
      val blob = Try(downloader.loadCachedBlob)
      blob shouldBe a[Success[_]]
      blob.get should not be null
    }
  }

}
