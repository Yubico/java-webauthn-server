package com.yubico.fido.metadata

import com.yubico.webauthn.TestAuthenticator
import com.yubico.webauthn.data.ByteArray
import com.yubico.webauthn.data.COSEAlgorithmIdentifier
import org.bouncycastle.asn1.x500.X500Name
import org.junit.runner.RunWith
import org.scalatest.FunSpec
import org.scalatest.Matchers
import org.scalatest.tags.Network
import org.scalatest.tags.Slow
import org.scalatestplus.junit.JUnitRunner

import java.nio.charset.StandardCharsets
import java.security.KeyPair
import java.security.cert.CRL
import java.security.cert.X509Certificate
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import scala.jdk.CollectionConverters.SetHasAsJava
import scala.jdk.OptionConverters.RichOptional

@Slow
@Network
@RunWith(classOf[JUnitRunner])
class FidoMds3Spec extends FunSpec with Matchers {

  private val CertValidFrom = Instant.parse("2022-02-15T17:00:00Z")
  private val CertValidTo = Instant.parse("2022-03-15T17:00:00Z")

  private def makeTrustRootCert(
      distinguishedName: String =
        "CN=Yubico java-webauthn-server unit tests, O=Yubico"
  ): (X509Certificate, KeyPair, X500Name) = {
    val keypair = TestAuthenticator.generateEcKeypair()
    val name = new X500Name(distinguishedName)
    (
      TestAuthenticator.buildCertificate(
        publicKey = keypair.getPublic,
        issuerName = name,
        subjectName = name,
        signingKey = keypair.getPrivate,
        signingAlg = COSEAlgorithmIdentifier.ES256,
        validFrom = CertValidFrom,
        validTo = CertValidTo,
      ),
      keypair,
      name,
    )
  }

  private def makeBlob(
      body: String
  ): (String, X509Certificate, java.util.Set[CRL]) = {
    val (cert, keypair, certName) = makeTrustRootCert()
    val header =
      s"""{"alg":"ES256","x5c": ["${new ByteArray(
        cert.getEncoded
      ).getBase64}"]}"""
    val blobTbs = new ByteArray(
      header.getBytes(StandardCharsets.UTF_8)
    ).getBase64Url + "." + new ByteArray(
      body.getBytes(StandardCharsets.UTF_8)
    ).getBase64Url
    val blobSignature = TestAuthenticator.sign(
      new ByteArray(blobTbs.getBytes(StandardCharsets.UTF_8)),
      keypair.getPrivate,
      COSEAlgorithmIdentifier.ES256,
    )
    (
      blobTbs + "." + blobSignature.getBase64Url,
      cert,
      Set(
        TestAuthenticator.buildCrl(
          certName,
          keypair.getPrivate,
          "SHA256withECDSA",
          CertValidFrom,
          CertValidTo,
        )
      ).asJava,
    )
  }

  describe("§3.2. Metadata BLOB object processing rules") {
    describe("8. Iterate through the individual entries (of type MetadataBLOBPayloadEntry). For each entry:") {
      ignore("1. Ignore the entry if the AAID, AAGUID or attestationCertificateKeyIdentifiers is not relevant to the relying party (e.g. not acceptable by any policy)") {
        fail("Test not implemented.")
      }

      describe("2.1. Check whether the status report of the authenticator model has changed compared to the cached entry by looking at the fields timeOfLastStatusChange and statusReport.") {
        it("Nothing to test - cache is implemented on the metadata BLOB as a whole.") {}
      }

      describe("2.2. Update the status of the cached entry. It is up to the relying party to specify behavior for authenticators with status reports that indicate a lack of certification, or known security issues. However, the status REVOKED indicates significant security issues related to such authenticators.") {
        it("Nothing to test for caching - cache is implemented on the metadata BLOB as a whole.") {}

        ignore("REVOKED authenticators are untrusted by default") {
          fail("Test not implemented.")
        }
      }

      describe("2.3. Note: Authenticators with an unacceptable status should be marked accordingly. This information is required for building registration and authentication policies included in the registration request and the authentication request [UAFProtocol].") {
        it("Nothing to test - status processing is left for library users to implement.") {}
      }

      describe("3. Update the cached metadata statement.") {
        it("Nothing to test - cache is implemented on the metadata BLOB as a whole.") {}
      }
    }
  }

  it("More [AuthenticatorTransport] values might be added in the future. FIDO Servers MUST silently ignore all unknown AuthenticatorStatus values.") {
    val (blobJwt, cert, crls) = makeBlob("""{
        "legalHeader" : "Kom ihåg att du aldrig får snyta dig i mattan!",
        "nextUpdate" : "2022-12-01",
        "no" : 0,
        "entries": [
          {
            "aaguid": "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            "statusReports": [
              {
                "status": "ARGHABLARGHLER",
                "effectiveDate": "2022-02-15"
              },
              {
                "status": "NOT_FIDO_CERTIFIED",
                "effectiveDate": "2022-02-16"
              }
            ],
            "timeOfLastStatusChange": "2022-02-15"
          }
        ]
      }""")
    val downloader: FidoMetadataDownloader = FidoMetadataDownloader
      .builder()
      .expectLegalHeader("Kom ihåg att du aldrig får snyta dig i mattan!")
      .useTrustRoot(cert)
      .useBlob(blobJwt)
      .clock(
        Clock.fixed(Instant.parse("2022-02-15T18:00:00Z"), ZoneOffset.UTC)
      )
      .useCrls(crls)
      .build()
    val mds =
      FidoMetadataService.builder().useDownloader(downloader).build()
    mds should not be null

    val entry = mds
      .findEntry(
        new AAGUID(ByteArray.fromHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
      )
      .toScala
    entry should not be None
    entry.get.getStatusReports should have size 1
    entry.get.getStatusReports.get(0).getStatus should be(
      AuthenticatorStatus.NOT_FIDO_CERTIFIED
    )
  }

}
