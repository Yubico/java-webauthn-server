package com.yubico.fido.metadata

import com.yubico.webauthn.TestAuthenticator
import com.yubico.webauthn.data.ByteArray
import com.yubico.webauthn.data.COSEAlgorithmIdentifier
import org.bouncycastle.asn1.x500.X500Name
import org.junit.runner.RunWith
import org.scalatest.FunSpec
import org.scalatest.Matchers
import org.scalatest.tags.Network
import org.scalatestplus.junit.JUnitRunner

import java.nio.charset.StandardCharsets
import java.security.KeyPair
import java.security.cert.CRL
import java.security.cert.CertPathValidatorException
import java.security.cert.CertPathValidatorException.BasicReason
import java.security.cert.X509Certificate
import java.time.Instant
import java.time.LocalDate
import scala.jdk.CollectionConverters.SeqHasAsJava

@Network
@RunWith(classOf[JUnitRunner])
class FidoMetadataDownloaderSpec extends FunSpec with Matchers {

  private def makeTrustRootCert(
      validFrom: Instant = Instant.now(),
      validTo: Instant = Instant.now().plusSeconds(600),
  ): (X509Certificate, KeyPair, X500Name) = {
    val keypair = TestAuthenticator.generateEcKeypair()
    val name = new X500Name(
      "CN=Yubico java-webauthn-server unit tests CA, O=Yubico"
    )
    (
      TestAuthenticator.buildCertificate(
        publicKey = keypair.getPublic,
        issuerName = name,
        subjectName = name,
        signingKey = keypair.getPrivate,
        signingAlg = COSEAlgorithmIdentifier.ES256,
        isCa = true,
        validFrom = validFrom,
        validTo = validTo,
      ),
      keypair,
      name,
    )
  }

  private def makeCert(
      caKeypair: KeyPair,
      caName: X500Name,
      validFrom: Instant = Instant.now(),
      validTo: Instant = Instant.now().plusSeconds(600),
      isCa: Boolean = false,
      name: String =
        "CN=Yubico java-webauthn-server unit tests blob cert, O=Yubico",
  ): (X509Certificate, KeyPair, X500Name) = {
    val keypair = TestAuthenticator.generateEcKeypair()
    val x500Name = new X500Name(name)
    (
      TestAuthenticator.buildCertificate(
        publicKey = keypair.getPublic,
        issuerName = caName,
        subjectName = x500Name,
        signingKey = caKeypair.getPrivate,
        signingAlg = COSEAlgorithmIdentifier.ES256,
        isCa = isCa,
        validFrom = validFrom,
        validTo = validTo,
      ),
      keypair,
      x500Name,
    )
  }

  private def makeBlob(
      certChain: List[X509Certificate],
      blobKeypair: KeyPair,
      nextUpdate: LocalDate,
  ) = {
    val blobHeader =
      s"""{"alg":"ES256","x5c": [${certChain
        .map(cert => new ByteArray(cert.getEncoded).getBase64)
        .mkString("\"", "\",\"", "\"")}]}"""
    val blobBody = s"""{
      "legalHeader": "Kom ihåg att du aldrig får snyta dig i mattan!",
      "no": 1,
      "nextUpdate": "${nextUpdate}",
      "entries": []
    }"""
    val blobTbs = new ByteArray(
      blobHeader.getBytes(StandardCharsets.UTF_8)
    ).getBase64Url + "." + new ByteArray(
      blobBody.getBytes(StandardCharsets.UTF_8)
    ).getBase64Url
    val blobSignature = TestAuthenticator.sign(
      new ByteArray(blobTbs.getBytes(StandardCharsets.UTF_8)),
      blobKeypair.getPrivate,
      COSEAlgorithmIdentifier.ES256,
    )
    blobTbs + "." + blobSignature.getBase64Url
  }

  describe("§3.2. Metadata BLOB object processing rules") {
    ignore("1. Download and cache the root signing trust anchor from the respective MDS root location e.g. More information can be found at https://fidoalliance.org/metadata/") {
      fail("Test not implemented.")
    }

    describe("2. To validate the digital certificates used in the digital signature, the certificate revocation information MUST be available in the form of CRLs at the respective MDS CRL location e.g. More information can be found at https://fidoalliance.org/metadata/") {
      ignore("SKIP: FIDO isn't currently publishing any CRLs at https://fidoalliance.org/metadata/ ...") {}
    }

    ignore("3. The FIDO Server MUST be able to download the latest metadata BLOB object from the well-known URL when appropriate, e.g. https://mds.fidoalliance.org/. The nextUpdate field of the Metadata BLOB specifies a date when the download SHOULD occur at latest.") {
      fail("Test not implemented.")
    }

    describe("4. If the x5u attribute is present in the JWT Header, then:") {

      ignore("1. The FIDO Server MUST verify that the URL specified by the x5u attribute has the same web-origin as the URL used to download the metadata BLOB from. The FIDO Server SHOULD ignore the file if the web-origin differs (in order to prevent loading objects from arbitrary sites).") {
        fail("Test not implemented.")
      }

      ignore("2. The FIDO Server MUST download the certificate (chain) from the URL specified by the x5u attribute [JWS]. The certificate chain MUST be verified to properly chain to the metadata BLOB signing trust anchor according to [RFC5280]. All certificates in the chain MUST be checked for revocation according to [RFC5280].") {
        fail("Test not implemented.")
      }

      ignore("3. The FIDO Server SHOULD ignore the file if the chain cannot be verified or if one of the chain certificates is revoked.") {
        fail("Test not implemented.")
      }

      ignore("Note: The requirements for verifying certificate revocation, are only applicable to the MDS BLOB payload certificates. It is up to the server vendors whether to enforce CRL check for the certificates in the individual metadata statements.") {
        fail("Test not implemented.")
      }
    }

    ignore("5. If the x5u attribute is missing, the chain should be retrieved from the x5c attribute. If that attribute is missing as well, Metadata BLOB signing trust anchor is considered the BLOB signing certificate chain.") {
      fail("Test not implemented.")
    }

    ignore("6. Verify the signature of the Metadata BLOB object using the BLOB signing certificate chain (as determined by the steps above). The FIDO Server SHOULD ignore the file if the signature is invalid. It SHOULD also ignore the file if its number (no) is less or equal to the number of the last Metadata BLOB object cached locally.") {
      fail("Test not implemented.")
    }

    ignore("7. Write the verified object to a local cache as required.") {
      fail("Test not implemented.")
    }

    describe("8. Iterate through the individual entries (of type MetadataBLOBPayloadEntry). For each entry:") {
      it("Nothing to test - see instead FidoMetadataService.") {}
    }
  }

  describe("FidoMetadataDownloader") {
    describe("can use an explicitly provided root cert and BLOB,") {

      val (trustRootCert, caKeypair, caName) = makeTrustRootCert()
      val (blobCert, blobKeypair, _) = makeCert(caKeypair, caName)
      val blobJwt =
        makeBlob(List(blobCert), blobKeypair, LocalDate.parse("2022-01-19"))

      it("but fails due to undetermined revocation status if the certs don't declare CRL distribution points.") {
        val thrown = the[CertPathValidatorException] thrownBy {
          FidoMetadataDownloader
            .builder()
            .expectLegalHeader("Kom ihåg att du aldrig får snyta dig i mattan!")
            .useTrustRoot(trustRootCert)
            .useBlob(blobJwt)
            .build()
            .loadBlob()
        }
        thrown.getReason should equal(
          BasicReason.UNDETERMINED_REVOCATION_STATUS
        )
      }

      it("and succeeds if explicitly given appropriate CRLs.") {
        val crls = List[CRL](
          TestAuthenticator.buildCrl(
            caName,
            caKeypair.getPrivate,
            "SHA256withECDSA",
            Instant.now(),
            Instant.now().plusSeconds(600),
          )
        )

        val blob = FidoMetadataDownloader
          .builder()
          .expectLegalHeader("Kom ihåg att du aldrig får snyta dig i mattan!")
          .useTrustRoot(trustRootCert)
          .useBlob(blobJwt)
          .useCrls(crls.asJava)
          .build()
          .loadBlob()
        blob should not be null
      }

      it("and fails if explicitly given CRLs where a cert in the chain is revoked.") {
        val crls = List[CRL](
          TestAuthenticator.buildCrl(
            caName,
            caKeypair.getPrivate,
            "SHA256withECDSA",
            Instant.now(),
            Instant.now().plusSeconds(600),
            revoked = Set(blobCert),
          )
        )

        val thrown = the[CertPathValidatorException] thrownBy {
          FidoMetadataDownloader
            .builder()
            .expectLegalHeader("Kom ihåg att du aldrig får snyta dig i mattan!")
            .useTrustRoot(trustRootCert)
            .useBlob(blobJwt)
            .useCrls(crls.asJava)
            .build()
            .loadBlob()
        }
        thrown.getReason should equal(
          BasicReason.REVOKED
        )
      }

      describe("and intermediate certificates") {

        val (intermediateCert, intermediateKeypair, intermediateName) =
          makeCert(
            caKeypair,
            caName,
            isCa = true,
            name = "CN=Yubico java-webauthn-server unit tests intermediate CA, O=Yubico",
          )
        val (blobCert, blobKeypair, _) =
          makeCert(intermediateKeypair, intermediateName)
        val blobJwt = makeBlob(
          List(blobCert, intermediateCert),
          blobKeypair,
          LocalDate.parse("2022-01-19"),
        )

        it("each require their own CRL.") {
          val thrown = the[CertPathValidatorException] thrownBy {
            FidoMetadataDownloader
              .builder()
              .expectLegalHeader(
                "Kom ihåg att du aldrig får snyta dig i mattan!"
              )
              .useTrustRoot(trustRootCert)
              .useBlob(blobJwt)
              .build()
              .loadBlob()
          }
          thrown.getReason should equal(
            BasicReason.UNDETERMINED_REVOCATION_STATUS
          )

          val rootCrl = TestAuthenticator.buildCrl(
            caName,
            caKeypair.getPrivate,
            "SHA256withECDSA",
            Instant.now(),
            Instant.now().plusSeconds(600),
          )
          val intermediateCrl = TestAuthenticator.buildCrl(
            intermediateName,
            intermediateKeypair.getPrivate,
            "SHA256withECDSA",
            Instant.now(),
            Instant.now().plusSeconds(600),
          )
          val crls = List(rootCrl, intermediateCrl)

          val blob = FidoMetadataDownloader
            .builder()
            .expectLegalHeader("Kom ihåg att du aldrig får snyta dig i mattan!")
            .useTrustRoot(trustRootCert)
            .useBlob(blobJwt)
            .useCrls(crls.asJava)
            .build()
            .loadBlob()
          blob should not be null
        }

        it("can revoke downstream certificates too.") {
          val rootCrl = TestAuthenticator.buildCrl(
            caName,
            caKeypair.getPrivate,
            "SHA256withECDSA",
            Instant.now(),
            Instant.now().plusSeconds(600),
          )
          val intermediateCrl = TestAuthenticator.buildCrl(
            intermediateName,
            intermediateKeypair.getPrivate,
            "SHA256withECDSA",
            Instant.now(),
            Instant.now().plusSeconds(600),
            revoked = Set(blobCert),
          )
          val crls = List(rootCrl, intermediateCrl)

          val thrown = the[CertPathValidatorException] thrownBy {
            FidoMetadataDownloader
              .builder()
              .expectLegalHeader(
                "Kom ihåg att du aldrig får snyta dig i mattan!"
              )
              .useTrustRoot(trustRootCert)
              .useBlob(blobJwt)
              .useCrls(crls.asJava)
              .build()
              .loadBlob()
          }
          thrown.getReason should equal(
            BasicReason.REVOKED
          )
        }
      }
    }
  }

}
