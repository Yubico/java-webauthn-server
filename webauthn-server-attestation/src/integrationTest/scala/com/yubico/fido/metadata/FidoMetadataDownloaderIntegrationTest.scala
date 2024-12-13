package com.yubico.fido.metadata

import com.yubico.internal.util.CertificateParser
import com.yubico.webauthn.data.ByteArray
import org.junit.runner.RunWith
import org.scalatest.BeforeAndAfter
import org.scalatest.funspec.AnyFunSpec
import org.scalatest.matchers.should.Matchers
import org.scalatest.tags.Network
import org.scalatest.tags.Slow
import org.scalatestplus.junit.JUnitRunner

import scala.jdk.CollectionConverters.ListHasAsScala
import scala.jdk.OptionConverters.RichOption
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
    // Cache downloaded items to avoid cause unnecessary load on remote servers
    var trustRootCache: Option[ByteArray] = None
    var blobCache: Option[ByteArray] = None
    val downloader =
      FidoMetadataDownloader
        .builder()
        .expectLegalHeader(
          "Retrieval and use of this BLOB indicates acceptance of the appropriate agreement located at https://fidoalliance.org/metadata/metadata-legal-terms/"
        )
        .useDefaultTrustRoot()
        .useTrustRootCache(
          () => trustRootCache.toJava,
          trustRoot => { trustRootCache = Some(trustRoot) },
        )
        .useDefaultBlob()
        .useBlobCache(
          () => blobCache.toJava,
          blob => { blobCache = Some(blob) },
        )
        .build()

    it("downloads and verifies the root cert and BLOB successfully.") {
      val blob = Try(downloader.loadCachedBlob)
      blob shouldBe a[Success[_]]
      blob.get should not be null
    }

    it(
      "does not encounter any CRLDistributionPoints entries in unknown format."
    ) {
      val blob = Try(downloader.loadCachedBlob)
      blob shouldBe a[Success[_]]
      val trustRootCert =
        CertificateParser.parseDer(trustRootCache.get.getBytes)
      val certChain = downloader
        .fetchHeaderCertChain(
          trustRootCert,
          FidoMetadataDownloader.parseBlob(blobCache.get).getBlob.getHeader,
        )
        .asScala :+ trustRootCert
      for { cert <- certChain } {
        withClue(
          s"Unknown CRLDistributionPoints structure in cert [${cert.getSubjectX500Principal}] : ${new ByteArray(cert.getEncoded)}"
        ) {
          CertificateParser
            .parseCrlDistributionPointsExtension(cert)
            .isAnyDistributionPointUnsupported should be(false)
        }
      }
    }
  }

}
