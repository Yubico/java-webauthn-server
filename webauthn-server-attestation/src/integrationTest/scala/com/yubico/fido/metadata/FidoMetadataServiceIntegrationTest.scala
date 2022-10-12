package com.yubico.fido.metadata

import com.fasterxml.jackson.databind.JsonNode
import com.yubico.fido.metadata.AttachmentHint.ATTACHMENT_HINT_EXTERNAL
import com.yubico.fido.metadata.AttachmentHint.ATTACHMENT_HINT_INTERNAL
import com.yubico.fido.metadata.AttachmentHint.ATTACHMENT_HINT_NFC
import com.yubico.fido.metadata.AttachmentHint.ATTACHMENT_HINT_WIRED
import com.yubico.fido.metadata.AttachmentHint.ATTACHMENT_HINT_WIRELESS
import com.yubico.internal.util.CertificateParser
import com.yubico.webauthn.FinishRegistrationOptions
import com.yubico.webauthn.RelyingParty
import com.yubico.webauthn.TestWithEachProvider
import com.yubico.webauthn.data.AttestationObject
import com.yubico.webauthn.test.Helpers
import com.yubico.webauthn.test.RealExamples
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.runner.RunWith
import org.scalatest.BeforeAndAfter
import org.scalatest.funspec.AnyFunSpec
import org.scalatest.matchers.should.Matchers
import org.scalatest.tags.Network
import org.scalatest.tags.Slow
import org.scalatestplus.junit.JUnitRunner

import java.io.IOException
import java.security.cert.X509Certificate
import java.time.Clock
import java.time.ZoneOffset
import java.util
import java.util.Optional
import scala.jdk.CollectionConverters.IteratorHasAsScala
import scala.jdk.CollectionConverters.SetHasAsJava
import scala.jdk.CollectionConverters.SetHasAsScala
import scala.jdk.OptionConverters.RichOptional
import scala.util.Try

@Slow
@Network
@RunWith(classOf[JUnitRunner])
class FidoMetadataServiceIntegrationTest
    extends AnyFunSpec
    with Matchers
    with BeforeAndAfter
    with TestWithEachProvider {

  describe("FidoMetadataService") {

    describe("downloaded with default settings") {
      val downloader = FidoMetadataDownloader
        .builder()
        .expectLegalHeader(
          "Retrieval and use of this BLOB indicates acceptance of the appropriate agreement located at https://fidoalliance.org/metadata/metadata-legal-terms/"
        )
        .useDefaultTrustRoot()
        .useTrustRootCache(() => Optional.empty(), _ => {})
        .useDefaultBlob()
        .useBlobCache(() => Optional.empty(), _ => {})
        .build()
      val fidoMds =
        Try(
          FidoMetadataService
            .builder()
            .useBlob(downloader.loadCachedBlob())
            .build()
        )

      val attachmentHintsUsb =
        Set(ATTACHMENT_HINT_EXTERNAL, ATTACHMENT_HINT_WIRED)
      val attachmentHintsNfc =
        attachmentHintsUsb ++ Set(ATTACHMENT_HINT_WIRELESS, ATTACHMENT_HINT_NFC)

      describe("correctly identifies and trusts") {
        def check(
            expectedDescriptionRegex: String,
            testData: RealExamples.Example,
            attachmentHints: Set[AttachmentHint],
        ): Unit = {

          def getAttestationTrustPath(
              attestationObject: AttestationObject
          ): Option[util.List[X509Certificate]] = {
            val x5cNode: JsonNode = getX5cArray(attestationObject)
            if (x5cNode != null && x5cNode.isArray) {
              val certs: util.List[X509Certificate] =
                new util.ArrayList[X509Certificate](x5cNode.size)
              for (binary <- x5cNode.elements().asScala) {
                if (binary.isBinary)
                  try certs.add(
                    CertificateParser.parseDer(binary.binaryValue)
                  )
                  catch {
                    case e: IOException =>
                      throw new RuntimeException(
                        "binary.isBinary() was true but binary.binaryValue() failed",
                        e,
                      )
                  }
                else
                  throw new IllegalArgumentException(
                    String.format(
                      "Each element of \"x5c\" property of attestation statement must be a binary value, was: %s",
                      binary.getNodeType,
                    )
                  )
              }
              Some(certs)
            } else None
          }

          def getX5cArray(attestationObject: AttestationObject): JsonNode =
            attestationObject.getAttestationStatement.get("x5c")

          val rp = RelyingParty
            .builder()
            .identity(testData.rp)
            .credentialRepository(Helpers.CredentialRepository.empty)
            .origins(
              Set(testData.attestation.collectedClientData.getOrigin).asJava
            )
            .allowUntrustedAttestation(false)
            .attestationTrustSource(fidoMds.get)
            .clock(
              Clock.fixed(
                CertificateParser
                  .parseDer(testData.attestationCert.getBytes)
                  .getNotBefore
                  .toInstant,
                ZoneOffset.UTC,
              )
            )
            .build()

          val registrationResult = rp.finishRegistration(
            FinishRegistrationOptions
              .builder()
              .request(testData.asRegistrationTestData.request)
              .response(testData.attestation.credential)
              .build()
          )

          registrationResult.isAttestationTrusted should be(true)

          val entries = fidoMds.get
            .findEntries(registrationResult)
            .asScala
          entries should not be empty
          val metadataStatements =
            entries.flatMap(_.getMetadataStatement.toScala)

          val descriptions =
            metadataStatements.flatMap(_.getDescription.toScala).toSet
          for { desc <- descriptions } {
            desc should (fullyMatch regex expectedDescriptionRegex)
          }

          metadataStatements
            .flatMap(_.getAttachmentHint.toScala.map(_.asScala))
            .flatten
            .toSet should equal(attachmentHints)
        }

        ignore("a YubiKey NEO.") { // TODO: Investigate why this fails
          check("YubiKey NEO", RealExamples.YubiKeyNeo, attachmentHintsNfc)
        }

        it("a YubiKey 4.") {
          check(
            "YK4 Series Key by Yubico",
            RealExamples.YubiKey4,
            attachmentHintsUsb,
          )
        }

        it("a YubiKey 5 NFC.") {
          check(
            "YubiKey 5 Series with NFC",
            RealExamples.YubiKey5,
            attachmentHintsNfc,
          )
        }

        it("an early YubiKey 5 NFC.") {
          check(
            "YubiKey 5 Series with NFC",
            RealExamples.YubiKey5Nfc,
            attachmentHintsNfc,
          )
        }

        it("a newer YubiKey 5 NFC.") {
          check(
            "YubiKey 5 Series with NFC",
            RealExamples.YubiKey5NfcPost5cNfc,
            attachmentHintsNfc,
          )
        }

        it("a YubiKey 5C NFC.") {
          check(
            "YubiKey 5 Series with NFC",
            RealExamples.YubiKey5cNfc,
            attachmentHintsNfc,
          )
        }

        it("a YubiKey 5 Nano.") {
          check(
            "YubiKey  ?5 Series",
            RealExamples.YubiKey5Nano,
            attachmentHintsUsb,
          )
        }

        it("a YubiKey 5Ci.") {
          check(
            "YubiKey 5 .*Lightning",
            RealExamples.YubiKey5Ci,
            attachmentHintsUsb,
          )
        }

        ignore("a Security Key by Yubico.") { // TODO: Investigate why this fails
          check(
            "Security Key by Yubico",
            RealExamples.SecurityKey,
            attachmentHintsUsb,
          )
        }

        it("a Security Key 2 by Yubico.") {
          check(
            "Security Key by Yubico",
            RealExamples.SecurityKey2,
            attachmentHintsUsb,
          )
        }

        ignore("a Security Key NFC by Yubico.") { // TODO: Investigate why this fails
          check(
            "Security Key NFC by Yubico",
            RealExamples.SecurityKeyNfc,
            attachmentHintsNfc,
          )
        }

        it("a YubiKey 5.4 NFC FIPS.") {
          withProviderContext(List(new BouncyCastleProvider)) { // Needed for JDK<14 because this example uses EdDSA
            check(
              "YubiKey 5 FIPS Series with NFC",
              RealExamples.YubikeyFips5Nfc,
              attachmentHintsNfc,
            )
          }
        }

        it("a YubiKey 5.4 Ci FIPS.") {
          check(
            "YubiKey 5 .*FIPS .*Lightning",
            RealExamples.Yubikey5ciFips,
            attachmentHintsUsb,
          )
        }

        it("a YubiKey Bio.") {
          check(
            "YubiKey Bio Series",
            RealExamples.YubikeyBio_5_5_5,
            attachmentHintsUsb,
          )
        }

        it("a Windows Hello attestation.") {
          check(
            "Windows Hello.*",
            RealExamples.WindowsHelloTpm,
            Set(ATTACHMENT_HINT_INTERNAL),
          )
        }
      }
    }
  }
}
