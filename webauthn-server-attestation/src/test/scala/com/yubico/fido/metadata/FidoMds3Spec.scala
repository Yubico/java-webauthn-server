package com.yubico.fido.metadata

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.node.ArrayNode
import com.fasterxml.jackson.databind.node.JsonNodeFactory
import com.fasterxml.jackson.databind.node.ObjectNode
import com.fasterxml.jackson.databind.node.TextNode
import com.yubico.fido.metadata.FidoMetadataService.Filters.AuthenticatorToBeFiltered
import com.yubico.internal.util.CertificateParser
import com.yubico.webauthn.FinishRegistrationOptions
import com.yubico.webauthn.RegistrationResult
import com.yubico.webauthn.RelyingParty
import com.yubico.webauthn.TestAuthenticator
import com.yubico.webauthn.TestAuthenticator.AttestationMaker
import com.yubico.webauthn.TestAuthenticator.AttestationSigner
import com.yubico.webauthn.data.ByteArray
import com.yubico.webauthn.data.COSEAlgorithmIdentifier
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions
import com.yubico.webauthn.data.PublicKeyCredentialParameters
import com.yubico.webauthn.data.RelyingPartyIdentity
import com.yubico.webauthn.data.UserIdentity
import com.yubico.webauthn.test.Helpers
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX500NameUtil
import org.junit.runner.RunWith
import org.scalatest.funspec.AnyFunSpec
import org.scalatest.matchers.should.Matchers
import org.scalatest.tags.Network
import org.scalatest.tags.Slow
import org.scalatestplus.junit.JUnitRunner

import java.nio.charset.StandardCharsets
import java.security.KeyPair
import java.security.cert.CRL
import java.security.cert.CertStore
import java.security.cert.CollectionCertStoreParameters
import java.security.cert.X509Certificate
import java.time.Clock
import java.time.Instant
import java.time.ZoneOffset
import java.util.Collections
import scala.collection.mutable
import scala.jdk.CollectionConverters.SeqHasAsJava
import scala.jdk.CollectionConverters.SetHasAsJava
import scala.jdk.CollectionConverters.SetHasAsScala
import scala.jdk.FunctionConverters.enrichAsJavaPredicate
import scala.jdk.OptionConverters.RichOption
import scala.jdk.OptionConverters.RichOptional

@Slow
@Network
@RunWith(classOf[JUnitRunner])
class FidoMds3Spec extends AnyFunSpec with Matchers {

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

  def makeDownloader(
      blobTuple: (String, X509Certificate, java.util.Set[CRL])
  ): FidoMetadataDownloader =
    blobTuple match {
      case (
            blobJwt: String,
            cert: X509Certificate,
            blobCrls: java.util.Set[CRL],
          ) =>
        FidoMetadataDownloader
          .builder()
          .expectLegalHeader(
            "Kom ihåg att du aldrig får snyta dig i mattan!"
          )
          .useTrustRoot(cert)
          .useBlob(blobJwt)
          .clock(
            Clock
              .fixed(
                Instant.parse("2022-02-22T18:00:00Z"),
                ZoneOffset.UTC,
              )
          )
          .useCrls(blobCrls)
          .build()
    }

  describe("§3.2. Metadata BLOB object processing rules") {
    describe("8. Iterate through the individual entries (of type MetadataBLOBPayloadEntry). For each entry:") {
      describe("1. Ignore the entry if the AAID, AAGUID or attestationCertificateKeyIdentifiers is not relevant to the relying party (e.g. not acceptable by any policy)") {
        val jf: JsonNodeFactory = JsonNodeFactory.instance

        val aaidA = new AAID("aaaa#0000")
        val aaidB = new AAID("bbbb#1111")
        val aaidC = new AAID("cccc#2222")

        val aaguidA =
          new AAGUID(ByteArray.fromHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
        val aaguidB =
          new AAGUID(ByteArray.fromHex("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"))
        val aaguidC =
          new AAGUID(ByteArray.fromHex("cccccccccccccccccccccccccccccccc"))

        val ackiA = Set("aa")
        val ackiB = Set("bb")
        val ackiC = Set("cc")

        def makeEntry(
            aaid: Option[AAID] = None,
            aaguid: Option[AAGUID] = None,
            acki: Option[Set[String]] = None,
        ): String = {
          val entry = JacksonCodecs
            .jsonWithDefaultEnums()
            .readTree(s"""{
             "metadataStatement": {
               "authenticatorVersion": 1,
               "attachmentHint" : ["internal"],
               "attestationRootCertificates": ["MIIB2DCCAX2gAwIBAgICAaswCgYIKoZIzj0EAwIwajEmMCQGA1UEAwwdWXViaWNvIFdlYkF1dGhuIHVuaXQgdGVzdHMgQ0ExDzANBgNVBAoMBll1YmljbzEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjELMAkGA1UEBhMCU0UwHhcNMTgwOTA2MTc0MjAwWhcNMTgwOTEzMTc0MjAwWjBqMSYwJAYDVQQDDB1ZdWJpY28gV2ViQXV0aG4gdW5pdCB0ZXN0cyBDQTEPMA0GA1UECgwGWXViaWNvMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMQswCQYDVQQGEwJTRTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABLtJrr5PYSc4KhmUcwBzgZgNadDnCs/ow2oh2jiKYUqq1A6hFcFf1NPfXLQjP2I4fBI36T6/QR2iY9mbqyP5iVejEzARMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSQAwRgIhANWaM2Tf2HPKc+ibCr8G4cxpQVr9Gib47a0CpqagCSCwAiEA3oKlX/ID94FKzgHvD2gyCKQU6RltAOMShVwoljj/5+E="],
               "attestationTypes" : ["basic_full"],
               "authenticationAlgorithms" : ["secp256r1_ecdsa_sha256_raw"],
               "description" : "Test authenticator",
               "keyProtection" : ["software"],
               "matcherProtection" : ["software"],
               "protocolFamily" : "u2f",
               "publicKeyAlgAndEncodings" : ["ecc_x962_raw"],
               "schema" : 3,
               "tcDisplay" : [],
               "upv" : [{ "major" : 1, "minor" : 1 }],
               "userVerificationDetails" : [[{ "userVerificationMethod" : "presence_internal" }]]
             },
             "statusReports": [],
             "timeOfLastStatusChange": "2022-02-21"
           }""")
            .asInstanceOf[ObjectNode]
          aaid.foreach(aaid =>
            entry.set[ObjectNode]("aaid", new TextNode(aaid.getValue))
          )
          aaguid.foreach(aaguid =>
            entry.set[ObjectNode]("aaguid", new TextNode(aaguid.asGuidString))
          )
          acki.foreach(acki =>
            entry.set[ObjectNode](
              "attestationCertificateKeyIdentifiers",
              new ArrayNode(
                jf,
                acki.toList.map[JsonNode](new TextNode(_)).asJava,
              ),
            )
          )
          JacksonCodecs.jsonWithDefaultEnums.writeValueAsString(entry)
        }

        def makeMds(
            blobTuple: (String, X509Certificate, java.util.Set[CRL]),
            attestationCrls: Set[CRL] = Set.empty,
        )(
            prefilter: MetadataBLOBPayloadEntry => Boolean,
            filter: Option[AuthenticatorToBeFiltered => Boolean] = None,
        ): FidoMetadataService = {
          val builder = FidoMetadataService
            .builder()
            .useBlob(makeDownloader(blobTuple).loadCachedBlob())
            .prefilter(prefilter.asJava)
            .certStore(
              CertStore.getInstance(
                "Collection",
                new CollectionCertStoreParameters(attestationCrls.asJava),
              )
            )
          filter.foreach(f => builder.filter(f.asJava))
          builder.build()
        }

        val blobTuple = makeBlob(s"""{
          "legalHeader" : "Kom ihåg att du aldrig får snyta dig i mattan!",
          "nextUpdate" : "2022-12-01",
          "no" : 0,
          "entries": [
            ${makeEntry(aaid = Some(aaidA))},
            ${makeEntry(aaguid = Some(aaguidA))},
            ${makeEntry(acki = Some(ackiA))},

            ${makeEntry(aaid = Some(aaidB), aaguid = Some(aaguidB))},
            ${makeEntry(aaguid = Some(aaguidB), acki = Some(ackiB))},
            ${makeEntry(aaid = Some(aaidB), acki = Some(ackiB))},

            ${makeEntry(
          aaid = Some(aaidC),
          aaguid = Some(aaguidC),
          acki = Some(ackiC),
        )}
          ]
        }""")

        it("Filtering in getFilteredEntries works as expected.") {
          def count(prefilter: MetadataBLOBPayloadEntry => Boolean): Long =
            makeMds(blobTuple)(prefilter).findEntries(_ => true).size

          implicit class MetadataBLOBPayloadEntryWithAbbreviatedAttestationCertificateKeyIdentifiers(
              entry: MetadataBLOBPayloadEntry
          ) {
            def getACKI: mutable.Set[String] =
              entry.getAttestationCertificateKeyIdentifiers.asScala
          }

          count(_ => false) should be(0)
          count(_ => true) should be(7)

          count(_.getAaid.toScala.contains(aaidA)) should be(1)
          count(_.getAaguid.toScala.contains(aaguidA)) should be(1)
          count(_.getACKI == ackiA) should be(1)

          count(_.getAaid.toScala.contains(aaidB)) should be(2)
          count(_.getAaguid.toScala.contains(aaguidB)) should be(2)
          count(_.getACKI == ackiB) should be(2)

          count(_.getAaid.toScala.contains(aaidC)) should be(1)
          count(_.getAaguid.toScala.contains(aaguidC)) should be(1)
          count(_.getACKI == ackiC) should be(1)

          count(entry =>
            entry.getAaid.toScala.contains(aaidA) || entry.getAaguid.toScala
              .contains(aaguidA) || entry.getACKI == ackiA
          ) should be(3)
          count(entry =>
            entry.getAaid.toScala.contains(aaidB) || entry.getAaguid.toScala
              .contains(aaguidB) || entry.getACKI == ackiB
          ) should be(3)
          count(entry =>
            entry.getAaid.toScala.contains(aaidC) || entry.getAaguid.toScala
              .contains(aaguidC) || entry.getACKI == ackiC
          ) should be(1)

          count(!_.getAaid.toScala.contains(aaidA)) should be(6)
          count(!_.getAaguid.toScala.contains(aaguidA)) should be(6)
          count(_.getACKI != ackiA) should be(6)

          count(!_.getAaid.toScala.contains(aaidB)) should be(5)
          count(!_.getAaguid.toScala.contains(aaguidB)) should be(5)
          count(_.getACKI != ackiB) should be(5)

          count(!_.getAaid.toScala.contains(aaidC)) should be(6)
          count(!_.getAaguid.toScala.contains(aaguidC)) should be(6)
          count(_.getACKI != ackiC) should be(6)

          makeMds(blobTuple)(
            _.getAaid.toScala.contains(aaidA)
          ).findEntries(_ => true).forEach(_.getAaid.get should be(aaidA))
          makeMds(blobTuple)(
            _.getAaguid.toScala.contains(aaguidB)
          ).findEntries(_ => true).forEach(_.getAaguid.get should be(aaguidB))
          makeMds(blobTuple)(
            _.getACKI == ackiC
          ).findEntries(_ => true).forEach(_.getAaguid.get should be(aaguidC))
        }

        it("Filtering correctly impacts the trust verdict in RelyingParty.finishRegistration.") {
          val rpIdentity = RelyingPartyIdentity
            .builder()
            .id(TestAuthenticator.Defaults.rpId)
            .name("Test RP")
            .build()
          val (pkc, _, attestationChain) =
            TestAuthenticator.createBasicAttestedCredential(
              aaguid = aaguidA.asBytes,
              attestationMaker = AttestationMaker.packed(
                AttestationSigner.ca(
                  COSEAlgorithmIdentifier.ES256,
                  aaguid = Some(aaguidA.asBytes),
                  validFrom = CertValidFrom,
                  validTo = CertValidTo,
                )
              ),
            )
          val attestationCrls = attestationChain.tail
            .map({
              case (cert, key) =>
                TestAuthenticator.buildCrl(
                  JcaX500NameUtil.getSubject(cert),
                  key,
                  "SHA256withECDSA",
                  CertValidFrom,
                  CertValidTo,
                )
            })
            .toSet
          val attestationRootBase64 =
            new ByteArray(attestationChain.last._1.getEncoded).getBase64

          val blobTuple = makeBlob(s"""{
          "legalHeader" : "Kom ihåg att du aldrig får snyta dig i mattan!",
          "nextUpdate" : "2022-12-01",
          "no" : 0,
          "entries": [{
             "aaguid": "${aaguidA.asHexString}",
             "metadataStatement": {
               "authenticatorVersion": 1,
               "attachmentHint" : ["internal"],
               "attestationRootCertificates": ["${attestationRootBase64}"],
               "attestationTypes" : ["basic_full"],
               "authenticationAlgorithms" : ["secp256r1_ecdsa_sha256_raw"],
               "description" : "Test authenticator",
               "keyProtection" : ["software"],
               "matcherProtection" : ["software"],
               "protocolFamily" : "u2f",
               "publicKeyAlgAndEncodings" : ["ecc_x962_raw"],
               "schema" : 3,
               "tcDisplay" : [],
               "upv" : [{ "major" : 1, "minor" : 1 }],
               "userVerificationDetails" : [[{ "userVerificationMethod" : "presence_internal" }]]
             },
             "statusReports": [],
             "timeOfLastStatusChange": "2022-02-21"
           }]
         }""")

          val finishRegistrationOptions = FinishRegistrationOptions
            .builder()
            .request(
              PublicKeyCredentialCreationOptions
                .builder()
                .rp(rpIdentity)
                .user(
                  UserIdentity
                    .builder()
                    .name("test")
                    .displayName("Test user")
                    .id(ByteArray.fromHex("01020304"))
                    .build()
                )
                .challenge(TestAuthenticator.Defaults.challenge)
                .pubKeyCredParams(
                  Collections.singletonList(PublicKeyCredentialParameters.ES256)
                )
                .build()
            )
            .response(pkc)
            .build()

          def finishRegistration(
              prefilter: MetadataBLOBPayloadEntry => Boolean
          ): RegistrationResult = {
            val mds =
              makeMds(blobTuple, attestationCrls = attestationCrls)(prefilter)
            RelyingParty
              .builder()
              .identity(rpIdentity)
              .credentialRepository(Helpers.CredentialRepository.empty)
              .attestationTrustSource(mds)
              .clock(Clock.fixed(CertValidFrom, ZoneOffset.UTC))
              .build()
              .finishRegistration(finishRegistrationOptions)
          }

          finishRegistration(
            _.getAaguid.toScala.contains(aaguidA)
          ).isAttestationTrusted should be(true)
          finishRegistration(
            _.getAaguid.toScala.contains(aaguidB)
          ).isAttestationTrusted should be(false)
        }

        describe("Zero AAGUIDs") {
          val zeroAaguid =
            new AAGUID(ByteArray.fromHex("00000000000000000000000000000000"))

          it("are not used to find metadata entries.") {
            aaguidA should not equal zeroAaguid

            val blobTuple = makeBlob(s"""{
              "legalHeader" : "Kom ihåg att du aldrig får snyta dig i mattan!",
              "nextUpdate" : "2022-12-01",
              "no" : 0,
              "entries": [
                ${makeEntry(aaguid = Some(aaguidA))},
                ${makeEntry(aaguid = Some(zeroAaguid))}
              ]
            }""")
            var filterRan = false
            val mds = makeMds(blobTuple)(
              _ => true,
              filter = Some({ _ =>
                filterRan = true
                true
              }),
            )

            mds.findEntries(zeroAaguid) shouldBe empty
            filterRan should be(false)
          }

          it("are omitted in the argument to the runtime filter.") {
            aaguidA should not equal zeroAaguid

            val (cert, _) = TestAuthenticator.generateAttestationCertificate()
            val acki: String = new ByteArray(
              CertificateParser.computeSubjectKeyIdentifier(cert)
            ).getHex
            val blobTuple = makeBlob(s"""{
              "legalHeader" : "Kom ihåg att du aldrig får snyta dig i mattan!",
              "nextUpdate" : "2022-12-01",
              "no" : 0,
              "entries": [
                ${makeEntry(acki = Some(Set(acki)), aaguid = Some(aaguidA))}
              ]
            }""")
            var filterRan = false
            val mds = makeMds(blobTuple)(
              _ => true,
              filter = Some({ authenticatorToBeFiltered =>
                filterRan = true
                authenticatorToBeFiltered.getAaguid.toScala should be(None)
                true
              }),
            )

            mds.findEntries(List(cert).asJava, zeroAaguid).size should be(1)
            filterRan should be(true)
          }
        }

      }

      describe("2.1. Check whether the status report of the authenticator model has changed compared to the cached entry by looking at the fields timeOfLastStatusChange and statusReport.") {
        it("Nothing to test - cache is implemented on the metadata BLOB as a whole.") {}
      }

      describe("2.2. Update the status of the cached entry. It is up to the relying party to specify behavior for authenticators with status reports that indicate a lack of certification, or known security issues. However, the status REVOKED indicates significant security issues related to such authenticators.") {
        it("Nothing to test for caching - cache is implemented on the metadata BLOB as a whole.") {}

        it("REVOKED authenticators are untrusted by default") {
          val aaguidA =
            new AAGUID(ByteArray.fromHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
          val aaguidB =
            new AAGUID(ByteArray.fromHex("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"))

          def makeMds(
              blobTuple: (String, X509Certificate, java.util.Set[CRL])
          ): FidoMetadataService =
            FidoMetadataService
              .builder()
              .useBlob(makeDownloader(blobTuple).loadCachedBlob())
              .build()

          val mds = makeMds(makeBlob(s"""{
              "legalHeader" : "Kom ihåg att du aldrig får snyta dig i mattan!",
              "nextUpdate" : "2022-12-01",
              "no" : 0,
              "entries": [
                {
                  "aaguid": "${aaguidA.asGuidString()}",
                  "metadataStatement": {
                    "authenticatorVersion": 1,
                    "attachmentHint" : ["internal"],
                    "attestationRootCertificates": ["MIIB2DCCAX2gAwIBAgICAaswCgYIKoZIzj0EAwIwajEmMCQGA1UEAwwdWXViaWNvIFdlYkF1dGhuIHVuaXQgdGVzdHMgQ0ExDzANBgNVBAoMBll1YmljbzEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjELMAkGA1UEBhMCU0UwHhcNMTgwOTA2MTc0MjAwWhcNMTgwOTEzMTc0MjAwWjBqMSYwJAYDVQQDDB1ZdWJpY28gV2ViQXV0aG4gdW5pdCB0ZXN0cyBDQTEPMA0GA1UECgwGWXViaWNvMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMQswCQYDVQQGEwJTRTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABLtJrr5PYSc4KhmUcwBzgZgNadDnCs/ow2oh2jiKYUqq1A6hFcFf1NPfXLQjP2I4fBI36T6/QR2iY9mbqyP5iVejEzARMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSQAwRgIhANWaM2Tf2HPKc+ibCr8G4cxpQVr9Gib47a0CpqagCSCwAiEA3oKlX/ID94FKzgHvD2gyCKQU6RltAOMShVwoljj/5+E="],
                    "attestationTypes" : ["basic_full"],
                    "authenticationAlgorithms" : ["secp256r1_ecdsa_sha256_raw"],
                    "description" : "Test authenticator",
                    "keyProtection" : ["software"],
                    "matcherProtection" : ["software"],
                     "protocolFamily" : "u2f",
                    "publicKeyAlgAndEncodings" : ["ecc_x962_raw"],
                    "schema" : 3,
                    "tcDisplay" : [],
                    "upv" : [{ "major" : 1, "minor" : 1 }],
                    "userVerificationDetails" : [[{ "userVerificationMethod" : "presence_internal" }]]
                  },
                  "statusReports": [],
                  "timeOfLastStatusChange": "2022-02-21"
                },
                {
                  "aaguid": "${aaguidB.asGuidString()}",
                  "metadataStatement": {
                    "authenticatorVersion": 1,
                    "attachmentHint" : ["internal"],
                    "attestationRootCertificates": ["MIIB2DCCAX2gAwIBAgICAaswCgYIKoZIzj0EAwIwajEmMCQGA1UEAwwdWXViaWNvIFdlYkF1dGhuIHVuaXQgdGVzdHMgQ0ExDzANBgNVBAoMBll1YmljbzEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjELMAkGA1UEBhMCU0UwHhcNMTgwOTA2MTc0MjAwWhcNMTgwOTEzMTc0MjAwWjBqMSYwJAYDVQQDDB1ZdWJpY28gV2ViQXV0aG4gdW5pdCB0ZXN0cyBDQTEPMA0GA1UECgwGWXViaWNvMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMQswCQYDVQQGEwJTRTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABLtJrr5PYSc4KhmUcwBzgZgNadDnCs/ow2oh2jiKYUqq1A6hFcFf1NPfXLQjP2I4fBI36T6/QR2iY9mbqyP5iVejEzARMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSQAwRgIhANWaM2Tf2HPKc+ibCr8G4cxpQVr9Gib47a0CpqagCSCwAiEA3oKlX/ID94FKzgHvD2gyCKQU6RltAOMShVwoljj/5+E="],
                    "attestationTypes" : ["basic_full"],
                    "authenticationAlgorithms" : ["secp256r1_ecdsa_sha256_raw"],
                    "description" : "Test authenticator",
                    "keyProtection" : ["software"],
                    "matcherProtection" : ["software"],
                     "protocolFamily" : "u2f",
                    "publicKeyAlgAndEncodings" : ["ecc_x962_raw"],
                    "schema" : 3,
                    "tcDisplay" : [],
                    "upv" : [{ "major" : 1, "minor" : 1 }],
                    "userVerificationDetails" : [[{ "userVerificationMethod" : "presence_internal" }]]
                  },
                  "statusReports": [{ "status": "REVOKED" }],
                  "timeOfLastStatusChange": "2022-02-21"
                }
              ]
            }"""))

          mds
            .findEntries(_ => true)
            .asScala
            .map(_.getAaguid.toScala) should equal(Set(Some(aaguidA)))
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
      FidoMetadataService.builder().useBlob(downloader.loadCachedBlob()).build()
    mds should not be null

    val entries = mds
      .findEntries(
        Collections.emptyList(),
        Some(
          new AAGUID(ByteArray.fromHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
        ).toJava,
      )
      .asScala
    entries should not be empty
    entries should have size 1
    entries.head.getStatusReports should have size 1
    entries.head.getStatusReports.get(0).getStatus should be(
      AuthenticatorStatus.NOT_FIDO_CERTIFIED
    )
  }

  describe("The Relying party MUST reject the Metadata Statement if the authenticatorVersion has not increased [with an UPDATE_AVAILABLE AuthenticatorStatus].") {

    val aaguid =
      new AAGUID(ByteArray.fromHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))

    def makeStatusReportsBlob(
        statusReports: String,
        timeOfLastStatusChange: String,
        authenticatorVersion: Int = 1,
    ): (String, X509Certificate, java.util.Set[CRL]) =
      makeBlob(s"""{
        "legalHeader" : "Kom ihåg att du aldrig får snyta dig i mattan!",
        "nextUpdate" : "2022-12-01",
        "no" : 0,
        "entries": [
          {
            "aaguid": "${aaguid.asGuidString}",
            "metadataStatement": {
              "authenticatorVersion": ${authenticatorVersion},
              "attachmentHint" : ["internal"],
              "attestationRootCertificates" : ["MIIB2DCCAX2gAwIBAgICAaswCgYIKoZIzj0EAwIwajEmMCQGA1UEAwwdWXViaWNvIFdlYkF1dGhuIHVuaXQgdGVzdHMgQ0ExDzANBgNVBAoMBll1YmljbzEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjELMAkGA1UEBhMCU0UwHhcNMTgwOTA2MTc0MjAwWhcNMTgwOTEzMTc0MjAwWjBqMSYwJAYDVQQDDB1ZdWJpY28gV2ViQXV0aG4gdW5pdCB0ZXN0cyBDQTEPMA0GA1UECgwGWXViaWNvMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMQswCQYDVQQGEwJTRTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABLtJrr5PYSc4KhmUcwBzgZgNadDnCs/ow2oh2jiKYUqq1A6hFcFf1NPfXLQjP2I4fBI36T6/QR2iY9mbqyP5iVejEzARMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSQAwRgIhANWaM2Tf2HPKc+ibCr8G4cxpQVr9Gib47a0CpqagCSCwAiEA3oKlX/ID94FKzgHvD2gyCKQU6RltAOMShVwoljj/5+E="],
              "attestationTypes" : ["basic_full"],
              "authenticationAlgorithms" : ["secp256r1_ecdsa_sha256_raw"],
              "description" : "Test authenticator",
              "keyProtection" : ["software"],
              "matcherProtection" : ["software"],
              "protocolFamily" : "u2f",
              "publicKeyAlgAndEncodings" : ["ecc_x962_raw"],
              "schema" : 3,
              "tcDisplay" : [],
              "upv" : [{ "major" : 1, "minor" : 1 }],
              "userVerificationDetails" : [[{ "userVerificationMethod" : "presence_internal" }]]
            },
            "statusReports": ${statusReports},
            "timeOfLastStatusChange": "${timeOfLastStatusChange}"
          }
        ]
      }""")

    def makeMds(
        blobTuple: (String, X509Certificate, java.util.Set[CRL])
    ): FidoMetadataService =
      FidoMetadataService
        .builder()
        .useBlob(makeDownloader(blobTuple).loadCachedBlob())
        .build()

    it("A metadata statement with UPDATE_AVAILABLE with authenticatorVersion greater than top-level authenticatorVersion is ignored.") {
      val mds = makeMds(
        makeStatusReportsBlob(
          """[
          {
            "status": "UPDATE_AVAILABLE",
            "effectiveDate": "2022-02-15",
            "authenticatorVersion": 2
          }
        ]""",
          "2022-02-16",
          authenticatorVersion = 1,
        )
      )

      mds
        .findEntries(Collections.emptyList(), Some(aaguid).toJava)
        .asScala shouldBe empty
    }

    it("A metadata statement with UPDATE_AVAILABLE with authenticatorVersion equal to top-level authenticatorVersion is accepted.") {
      val mds = makeMds(
        makeStatusReportsBlob(
          """[
          {
            "status": "UPDATE_AVAILABLE",
            "effectiveDate": "2022-02-15",
            "authenticatorVersion": 2
          }
        ]""",
          "2022-02-16",
          authenticatorVersion = 2,
        )
      )

      mds
        .findEntries(Collections.emptyList(), Some(aaguid).toJava)
        .asScala should not be empty
    }

    it("A metadata statement with UPDATE_AVAILABLE with authenticatorVersion less than top-level authenticatorVersion is accepted.") {
      val mds = makeMds(
        makeStatusReportsBlob(
          """[
          {
            "status": "UPDATE_AVAILABLE",
            "effectiveDate": "2022-02-15",
            "authenticatorVersion": 2
          }
        ]""",
          "2022-02-16",
          authenticatorVersion = 3,
        )
      )

      mds
        .findEntries(Collections.emptyList(), Some(aaguid).toJava)
        .asScala should not be empty
    }
  }

  describe("The noAttestationKeyCompromise filter") {

    val attestationRoot = TestAuthenticator.generateAttestationCaCertificate()
    val rootCertBase64 = new ByteArray(attestationRoot._1.getEncoded).getBase64

    val (compromisedCert, _) =
      TestAuthenticator.generateAttestationCertificate(
        name = new X500Name("CN=Compromised cert 1"),
        caCertAndKey = Some(attestationRoot),
      )
    val (goodCert, _) = TestAuthenticator.generateAttestationCertificate(
      name = new X500Name("CN=Good cert"),
      caCertAndKey = Some(attestationRoot),
    )

    val (compromisedCert2a, _) =
      TestAuthenticator.generateAttestationCertificate(
        name = new X500Name("CN=Compromised cert 2a"),
        caCertAndKey = Some(attestationRoot),
      )
    val (compromisedCert2b, _) =
      TestAuthenticator.generateAttestationCertificate(
        name = new X500Name("CN=Compromised cert 2b"),
        caCertAndKey = Some(attestationRoot),
      )

    val (unrelatedCert, _) =
      TestAuthenticator.generateAttestationCertificate(name =
        new X500Name("CN=Unrelated cert")
      )

    val compromisedCertKeyIdentifier = new ByteArray(
      CertificateParser.computeSubjectKeyIdentifier(compromisedCert)
    ).getHex
    val compromisedCert2aKeyIdentifier = new ByteArray(
      CertificateParser.computeSubjectKeyIdentifier(compromisedCert2a)
    ).getHex
    val compromisedCert2bKeyIdentifier = new ByteArray(
      CertificateParser.computeSubjectKeyIdentifier(compromisedCert2b)
    ).getHex
    val goodCertKeyIdentifier = new ByteArray(
      CertificateParser.computeSubjectKeyIdentifier(goodCert)
    ).getHex

    val aaguidA =
      new AAGUID(ByteArray.fromHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"))
    val aaguidB =
      new AAGUID(ByteArray.fromHex("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"))
    val aaguidC =
      new AAGUID(ByteArray.fromHex("cccccccccccccccccccccccccccccccc"))

    val blob: MetadataBLOBPayload =
      JacksonCodecs.jsonWithDefaultEnums.readValue(
        s"""{
        "legalHeader" : "Kom ihåg att du aldrig får snyta dig i mattan!",
        "nextUpdate" : "2022-12-01",
        "no" : 0,
        "entries": [
          {
            "aaguid": "${aaguidA.asGuidString()}",
            "attestationCertificateKeyIdentifiers": ["${goodCertKeyIdentifier}"],
            "metadataStatement": {
              "aaguid": "${aaguidA.asGuidString()}",
              "attestationCertificateKeyIdentifiers": ["${goodCertKeyIdentifier}"],
              "authenticatorVersion": 1,
              "attachmentHint" : ["internal"],
              "attestationRootCertificates": ["${rootCertBase64}"],
              "attestationTypes" : ["basic_full"],
              "authenticationAlgorithms" : ["secp256r1_ecdsa_sha256_raw"],
              "description" : "Test authenticator",
              "keyProtection" : ["software"],
              "matcherProtection" : ["software"],
              "protocolFamily" : "u2f",
              "publicKeyAlgAndEncodings" : ["ecc_x962_raw"],
              "schema" : 3,
              "tcDisplay" : [],
              "upv" : [{ "major" : 1, "minor" : 1 }],
              "userVerificationDetails" : [[{ "userVerificationMethod" : "presence_internal" }]]
            },
            "statusReports": [],
            "timeOfLastStatusChange": "2022-02-15"
          },

          {
            "aaguid": "${aaguidB.asGuidString()}",
            "attestationCertificateKeyIdentifiers": ["${compromisedCertKeyIdentifier}"],
            "metadataStatement": {
              "aaguid": "${aaguidB.asGuidString()}",
              "attestationCertificateKeyIdentifiers": ["${compromisedCertKeyIdentifier}"],
              "authenticatorVersion": 1,
              "attachmentHint" : ["internal"],
              "attestationRootCertificates": ["${rootCertBase64}"],
              "attestationTypes" : ["basic_full"],
              "authenticationAlgorithms" : ["secp256r1_ecdsa_sha256_raw"],
              "description" : "Test authenticator",
              "keyProtection" : ["software"],
              "matcherProtection" : ["software"],
              "protocolFamily" : "u2f",
              "publicKeyAlgAndEncodings" : ["ecc_x962_raw"],
              "schema" : 3,
              "tcDisplay" : [],
              "upv" : [{ "major" : 1, "minor" : 1 }],
              "userVerificationDetails" : [[{ "userVerificationMethod" : "presence_internal" }]]
            },
            "statusReports": [
              {
                "status": "ATTESTATION_KEY_COMPROMISE",
                "certificate": "${new ByteArray(compromisedCert.getEncoded).getBase64}"
              }
            ],
            "timeOfLastStatusChange": "2022-02-15"
          },

          {
            "aaguid": "${aaguidC.asGuidString()}",
            "attestationCertificateKeyIdentifiers": ["${compromisedCert2aKeyIdentifier}"],
            "metadataStatement": {
              "aaguid": "${aaguidC.asGuidString()}",
              "attestationCertificateKeyIdentifiers": ["${compromisedCert2bKeyIdentifier}"],
              "authenticatorVersion": 1,
              "attachmentHint" : ["internal"],
              "attestationRootCertificates": ["${rootCertBase64}"],
              "attestationTypes" : ["basic_full"],
              "authenticationAlgorithms" : ["secp256r1_ecdsa_sha256_raw"],
              "description" : "Test authenticator",
              "keyProtection" : ["software"],
              "matcherProtection" : ["software"],
              "protocolFamily" : "u2f",
              "publicKeyAlgAndEncodings" : ["ecc_x962_raw"],
              "schema" : 3,
              "tcDisplay" : [],
              "upv" : [{ "major" : 1, "minor" : 1 }],
              "userVerificationDetails" : [[{ "userVerificationMethod" : "presence_internal" }]]
            },
            "statusReports": [
              { "status": "ATTESTATION_KEY_COMPROMISE" }
            ],
            "timeOfLastStatusChange": "2022-02-15"
          }
        ]
      }""".stripMargin,
        classOf[MetadataBLOBPayload],
      )

    it("is enabled by default.") {
      val mds = FidoMetadataService.builder().useBlob(blob).build()

      mds
        .findTrustRoots(
          List(unrelatedCert).asJava,
          Some(aaguidA.asBytes).toJava,
        )
        .getTrustRoots
        .asScala should not be empty

      mds
        .findTrustRoots(
          List(goodCert).asJava,
          None.toJava,
        )
        .getTrustRoots
        .asScala should not be empty

      mds
        .findTrustRoots(
          List(compromisedCert).asJava,
          Some(aaguidB.asBytes).toJava,
        )
        .getTrustRoots
        .asScala shouldBe empty

      mds
        .findTrustRoots(
          List(unrelatedCert).asJava,
          Some(aaguidC.asBytes).toJava,
        )
        .getTrustRoots
        .asScala shouldBe empty

      mds
        .findTrustRoots(
          List(compromisedCert).asJava,
          None.toJava,
        )
        .getTrustRoots
        .asScala shouldBe empty

      mds
        .findTrustRoots(
          List(compromisedCert2a).asJava,
          None.toJava,
        )
        .getTrustRoots
        .asScala shouldBe empty

      mds
        .findTrustRoots(
          List(compromisedCert2b).asJava,
          None.toJava,
        )
        .getTrustRoots
        .asScala shouldBe empty
    }

    it("can be enabled explicitly.") {
      val mds = FidoMetadataService
        .builder()
        .useBlob(blob)
        .filter(FidoMetadataService.Filters.noAttestationKeyCompromise())
        .build()

      mds
        .findTrustRoots(
          List(goodCert).asJava,
          Some(aaguidA.asBytes).toJava,
        )
        .getTrustRoots
        .asScala should not be empty

      mds
        .findTrustRoots(
          List(compromisedCert).asJava,
          Some(aaguidB.asBytes).toJava,
        )
        .getTrustRoots
        .asScala shouldBe empty

      mds
        .findTrustRoots(
          List(unrelatedCert).asJava,
          Some(aaguidC.asBytes).toJava,
        )
        .getTrustRoots
        .asScala shouldBe empty
    }

    it("can be overridden with a different filter.") {
      val mds =
        FidoMetadataService.builder().useBlob(blob).filter(_ => true).build()

      mds
        .findTrustRoots(
          List(compromisedCert).asJava,
          Some(aaguidB.asBytes).toJava,
        )
        .getTrustRoots
        .asScala should not be empty

      mds
        .findTrustRoots(
          List(compromisedCert).asJava,
          Some(aaguidB.asBytes).toJava,
        )
        .getTrustRoots
        .asScala should not be empty

      mds
        .findTrustRoots(
          List(unrelatedCert).asJava,
          Some(aaguidC.asBytes).toJava,
        )
        .getTrustRoots
        .asScala should not be empty
    }

  }

}
