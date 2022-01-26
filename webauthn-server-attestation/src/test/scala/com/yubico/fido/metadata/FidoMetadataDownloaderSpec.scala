package com.yubico.fido.metadata

import com.yubico.webauthn.TestAuthenticator
import com.yubico.webauthn.data.ByteArray
import com.yubico.webauthn.data.COSEAlgorithmIdentifier
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.bouncycastle.asn1.x500.X500Name
import org.eclipse.jetty.server.HttpConfiguration
import org.eclipse.jetty.server.HttpConnectionFactory
import org.eclipse.jetty.server.Request
import org.eclipse.jetty.server.SecureRequestCustomizer
import org.eclipse.jetty.server.Server
import org.eclipse.jetty.server.ServerConnector
import org.eclipse.jetty.server.SslConnectionFactory
import org.eclipse.jetty.server.handler.AbstractHandler
import org.eclipse.jetty.util.ssl.SslContextFactory
import org.eclipse.jetty.util.thread.QueuedThreadPool
import org.junit.runner.RunWith
import org.scalatest.BeforeAndAfter
import org.scalatest.FunSpec
import org.scalatest.Matchers
import org.scalatest.tags.Network
import org.scalatestplus.junit.JUnitRunner

import java.net.URL
import java.nio.charset.StandardCharsets
import java.security.KeyPair
import java.security.KeyStore
import java.security.SecureRandom
import java.security.cert.CRL
import java.security.cert.CertPathValidatorException
import java.security.cert.CertPathValidatorException.BasicReason
import java.security.cert.X509Certificate
import java.time.Clock
import java.time.Instant
import java.time.LocalDate
import java.time.ZoneOffset
import java.util.Optional
import scala.jdk.CollectionConverters.SeqHasAsJava

@Network
@RunWith(classOf[JUnitRunner])
class FidoMetadataDownloaderSpec
    extends FunSpec
    with Matchers
    with BeforeAndAfter {

  var httpServer: Option[Server] = None
  after {
    for { server <- httpServer } {
      server.stop()
    }
    httpServer = None
  }
  private def startServer(server: Server): Unit = {
    httpServer = Some(server)
    server.start()
  }

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
      legalHeader: String = "Kom ihåg att du aldrig får snyta dig i mattan!",
      no: Int = 1,
  ) = {
    val blobHeader =
      s"""{"alg":"ES256","x5c": [${certChain
        .map(cert => new ByteArray(cert.getEncoded).getBase64)
        .mkString("\"", "\",\"", "\"")}]}"""
    val blobBody = s"""{
      "legalHeader": "${legalHeader}",
      "no": ${no},
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

  private def makeHttpServer(
      path: String,
      response: String,
  ): (Server, String, X509Certificate) =
    makeHttpServer(Map(path -> response.getBytes(StandardCharsets.UTF_8)))
  private def makeHttpServer(
      responses: Map[String, Array[Byte]]
  ): (Server, String, X509Certificate) = {
    val tlsKey = TestAuthenticator.generateEcKeypair()
    val tlsCert = TestAuthenticator.buildCertificate(
      tlsKey.getPublic,
      new X500Name("CN=localhost"),
      new X500Name("CN=localhost"),
      tlsKey.getPrivate,
      signingAlg = COSEAlgorithmIdentifier.ES256,
    )
    val keystorePassword = "foo"
    val keyStore = KeyStore.getInstance(KeyStore.getDefaultType)
    keyStore.load(null)
    keyStore.setKeyEntry(
      "default",
      tlsKey.getPrivate,
      keystorePassword.toCharArray,
      Array(tlsCert),
    )

    val httpConfig = new HttpConfiguration()
    httpConfig.addCustomizer(new SecureRequestCustomizer())
    val http11 = new HttpConnectionFactory(httpConfig)
    val sslContextFactory = new SslContextFactory.Server()
    sslContextFactory.setKeyStore(keyStore)
    sslContextFactory.setKeyStorePassword(keystorePassword)
    val tls = new SslConnectionFactory(sslContextFactory, http11.getProtocol)

    val threadPool = new QueuedThreadPool()
    threadPool.setName("server")
    val server = new Server(threadPool)
    val connector = new ServerConnector(server, tls, http11)
    val port = 8443
    connector.setPort(port)
    server.addConnector(connector)
    server.setHandler(new AbstractHandler {
      override def handle(
          target: String,
          jettyRequest: Request,
          request: HttpServletRequest,
          response: HttpServletResponse,
      ): Unit = {
        responses.get(target) match {
          case Some(responseBody) => {
            response.getOutputStream.write(responseBody)
            response.setStatus(200)
          }
          case None => response.setStatus(404)
        }

        jettyRequest.setHandled(true)
      }
    })

    (server, s"https://localhost:${port}", tlsCert)
  }

  describe("§3.2. Metadata BLOB object processing rules") {
    ignore("1. Download and cache the root signing trust anchor from the respective MDS root location e.g. More information can be found at https://fidoalliance.org/metadata/") {
      fail("Test not implemented.")
    }

    describe("2. To validate the digital certificates used in the digital signature, the certificate revocation information MUST be available in the form of CRLs at the respective MDS CRL location e.g. More information can be found at https://fidoalliance.org/metadata/") {
      val (trustRootCert, caKeypair, caName) = makeTrustRootCert()
      val (blobCert, blobKeypair, _) = makeCert(caKeypair, caName)
      val blobJwt =
        makeBlob(List(blobCert), blobKeypair, LocalDate.parse("2022-01-19"))

      it(
        "Verification fails if the certs don't declare CRL distribution points."
      ) {
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

      it("Verification succeeds if explicitly given appropriate CRLs.") {
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

      it("Verification fails if explicitly given CRLs where a cert in the chain is revoked.") {
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

      describe("Intermediate certificates") {

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

    describe("3. The FIDO Server MUST be able to download the latest metadata BLOB object from the well-known URL when appropriate, e.g. https://mds.fidoalliance.org/. The nextUpdate field of the Metadata BLOB specifies a date when the download SHOULD occur at latest.") {
      it("The BLOB is downloaded if there isn't a cached one.") {
        val random = new SecureRandom()
        val blobLegalHeader =
          s"Kom ihåg att du aldrig får snyta dig i mattan! ${random.nextInt(10000)}"
        val blobNo = random.nextInt(10000);

        val (trustRootCert, caKeypair, caName) = makeTrustRootCert()
        val (blobCert, blobKeypair, _) = makeCert(caKeypair, caName)
        val blobJwt =
          makeBlob(
            List(blobCert),
            blobKeypair,
            LocalDate.parse("2022-01-19"),
            no = blobNo,
            legalHeader = blobLegalHeader,
          )
        val crls = List[CRL](
          TestAuthenticator.buildCrl(
            caName,
            caKeypair.getPrivate,
            "SHA256withECDSA",
            Instant.now(),
            Instant.now().plusSeconds(600),
          )
        )

        val (server, serverUrl, httpsCert) =
          makeHttpServer("/blob.jwt", blobJwt)
        startServer(server)

        val blob = FidoMetadataDownloader
          .builder()
          .expectLegalHeader(blobLegalHeader)
          .useTrustRoot(trustRootCert)
          .downloadBlob(new URL(s"${serverUrl}/blob.jwt"))
          .useBlobCache(() => Optional.empty(), _ => {})
          .useCrls(crls.asJava)
          .trustHttpsCerts(httpsCert)
          .build()
          .loadBlob()
        blob should not be null
        blob.getLegalHeader should equal(blobLegalHeader)
        blob.getNo should equal(blobNo)
      }

      it("The BLOB is downloaded if the cached one is out of date.") {
        val oldBlobNo = 1
        val newBlobNo = 2

        val (trustRootCert, caKeypair, caName) = makeTrustRootCert()
        val (blobCert, blobKeypair, _) = makeCert(caKeypair, caName)
        val oldBlobJwt =
          makeBlob(
            List(blobCert),
            blobKeypair,
            LocalDate.parse("2022-01-19"),
            no = oldBlobNo,
          )
        val newBlobJwt =
          makeBlob(
            List(blobCert),
            blobKeypair,
            LocalDate.parse("2022-01-20"),
            no = newBlobNo,
          )
        val crls = List[CRL](
          TestAuthenticator.buildCrl(
            caName,
            caKeypair.getPrivate,
            "SHA256withECDSA",
            Instant.now(),
            Instant.now().plusSeconds(600),
          )
        )

        val (server, serverUrl, httpsCert) =
          makeHttpServer("/blob.jwt", newBlobJwt)
        startServer(server)

        val blob = FidoMetadataDownloader
          .builder()
          .expectLegalHeader("Kom ihåg att du aldrig får snyta dig i mattan!")
          .useTrustRoot(trustRootCert)
          .downloadBlob(new URL(s"${serverUrl}/blob.jwt"))
          .useBlobCache(
            () =>
              Optional.of(
                new ByteArray(oldBlobJwt.getBytes(StandardCharsets.UTF_8))
              ),
            _ => {},
          )
          .clock(
            Clock.fixed(Instant.parse("2022-01-19T00:00:00Z"), ZoneOffset.UTC)
          )
          .useCrls(crls.asJava)
          .trustHttpsCerts(httpsCert)
          .build()
          .loadBlob()
        blob should not be null
        blob.getNo should equal(newBlobNo)
      }

      it(
        "The BLOB is not downloaded if the cached one is not yet out of date."
      ) {
        val oldBlobNo = 1
        val newBlobNo = 2

        val (trustRootCert, caKeypair, caName) = makeTrustRootCert()
        val (blobCert, blobKeypair, _) = makeCert(caKeypair, caName)
        val oldBlobJwt =
          makeBlob(
            List(blobCert),
            blobKeypair,
            LocalDate.parse("2022-01-19"),
            no = oldBlobNo,
          )
        val newBlobJwt =
          makeBlob(
            List(blobCert),
            blobKeypair,
            LocalDate.parse("2022-01-20"),
            no = newBlobNo,
          )
        val crls = List[CRL](
          TestAuthenticator.buildCrl(
            caName,
            caKeypair.getPrivate,
            "SHA256withECDSA",
            Instant.now(),
            Instant.now().plusSeconds(600),
          )
        )

        val (server, serverUrl, httpsCert) =
          makeHttpServer("/blob.jwt", newBlobJwt)
        startServer(server)

        val blob = FidoMetadataDownloader
          .builder()
          .expectLegalHeader("Kom ihåg att du aldrig får snyta dig i mattan!")
          .useTrustRoot(trustRootCert)
          .downloadBlob(new URL(s"${serverUrl}/blob.jwt"))
          .useBlobCache(
            () =>
              Optional.of(
                new ByteArray(oldBlobJwt.getBytes(StandardCharsets.UTF_8))
              ),
            _ => {},
          )
          .clock(
            Clock.fixed(Instant.parse("2022-01-18T00:00:00Z"), ZoneOffset.UTC)
          )
          .useCrls(crls.asJava)
          .trustHttpsCerts(httpsCert)
          .build()
          .loadBlob()
        blob should not be null
        blob.getNo should equal(oldBlobNo)
      }

      it("""A newly downloaded BLOB is disregarded if the cached one has a greater "no".""") {
        val oldBlobNo = 2
        val newBlobNo = 1

        val (trustRootCert, caKeypair, caName) = makeTrustRootCert()
        val (blobCert, blobKeypair, _) = makeCert(caKeypair, caName)
        val oldBlobJwt =
          makeBlob(
            List(blobCert),
            blobKeypair,
            LocalDate.parse("2022-01-19"),
            no = oldBlobNo,
          )
        val newBlobJwt =
          makeBlob(
            List(blobCert),
            blobKeypair,
            LocalDate.parse("2022-01-20"),
            no = newBlobNo,
          )
        val crls = List[CRL](
          TestAuthenticator.buildCrl(
            caName,
            caKeypair.getPrivate,
            "SHA256withECDSA",
            Instant.now(),
            Instant.now().plusSeconds(600),
          )
        )

        val (server, serverUrl, httpsCert) =
          makeHttpServer("/blob.jwt", newBlobJwt)
        startServer(server)

        val blob = FidoMetadataDownloader
          .builder()
          .expectLegalHeader("Kom ihåg att du aldrig får snyta dig i mattan!")
          .useTrustRoot(trustRootCert)
          .downloadBlob(new URL(s"${serverUrl}/blob.jwt"))
          .useBlobCache(
            () =>
              Optional.of(
                new ByteArray(oldBlobJwt.getBytes(StandardCharsets.UTF_8))
              ),
            _ => {},
          )
          .clock(
            Clock.fixed(Instant.parse("2022-01-19T00:00:00Z"), ZoneOffset.UTC)
          )
          .useCrls(crls.asJava)
          .trustHttpsCerts(httpsCert)
          .build()
          .loadBlob()
        blob should not be null
        blob.getNo should equal(oldBlobNo)
      }
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

}
