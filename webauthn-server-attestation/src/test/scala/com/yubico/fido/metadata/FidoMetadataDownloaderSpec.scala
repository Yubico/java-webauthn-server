package com.yubico.fido.metadata

import com.fasterxml.jackson.databind.node.IntNode
import com.fasterxml.jackson.databind.node.ObjectNode
import com.yubico.fido.metadata.FidoMetadataDownloaderException.Reason
import com.yubico.internal.util.BinaryUtil
import com.yubico.internal.util.JacksonCodecs
import com.yubico.webauthn.TestAuthenticator
import com.yubico.webauthn.data.ByteArray
import com.yubico.webauthn.data.COSEAlgorithmIdentifier
import org.bouncycastle.asn1.x500.X500Name
import org.eclipse.jetty.http.HttpStatus
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
import org.scalatest.funspec.AnyFunSpec
import org.scalatest.matchers.should.Matchers
import org.scalatest.tags.Network
import org.scalatestplus.junit.JUnitRunner

import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.URL
import java.nio.charset.StandardCharsets
import java.security.DigestException
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
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import scala.jdk.CollectionConverters.ListHasAsScala
import scala.jdk.CollectionConverters.SeqHasAsJava
import scala.jdk.CollectionConverters.SetHasAsJava
import scala.util.Success
import scala.util.Try

@Network
@RunWith(classOf[JUnitRunner])
class FidoMetadataDownloaderSpec
    extends AnyFunSpec
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

  val CertValidFrom: Instant = Instant.parse("2022-02-18T12:00:00Z")
  val CertValidTo: Instant = Instant.parse("2022-03-20T12:00:00Z")

  private def makeTrustRootCert(
      distinguishedName: String =
        "CN=Yubico java-webauthn-server unit tests CA, O=Yubico",
      validFrom: Instant = CertValidFrom,
      validTo: Instant = CertValidTo,
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
      validFrom: Instant = CertValidFrom,
      validTo: Instant = CertValidTo,
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

  private def makeCertChain(
      caKeypair: KeyPair,
      caName: X500Name,
      chainLength: Int,
      validFrom: Instant = CertValidFrom,
      validTo: Instant = CertValidTo,
      leafName: String =
        "CN=Yubico java-webauthn-server unit tests blob cert, O=Yubico",
  ): List[(X509Certificate, KeyPair, X500Name)] = {
    var certs: List[(X509Certificate, KeyPair, X500Name)] = Nil
    var currentKeypair = caKeypair
    var currentName = caName

    for { i <- 1 to chainLength } {
      val (cert, keypair, name) = makeCert(
        currentKeypair,
        currentName,
        validFrom = validFrom,
        validTo = validTo,
        name =
          if (i == chainLength) leafName else s"CN=Test intermediate CA ${i}",
        isCa = i != chainLength,
      )
      certs = (cert, keypair, name) +: certs
      currentKeypair = keypair
      currentName = name
    }

    certs
  }

  private def makeBlob(
      blobKeypair: KeyPair,
      header: String,
      body: String,
  ): String = {
    val blobTbs = new ByteArray(
      header.getBytes(StandardCharsets.UTF_8)
    ).getBase64Url + "." + new ByteArray(
      body.getBytes(StandardCharsets.UTF_8)
    ).getBase64Url
    val blobSignature = TestAuthenticator.sign(
      new ByteArray(blobTbs.getBytes(StandardCharsets.UTF_8)),
      blobKeypair.getPrivate,
      COSEAlgorithmIdentifier.ES256,
    )
    blobTbs + "." + blobSignature.getBase64Url
  }

  private def makeBlob(
      certChain: List[X509Certificate],
      blobKeypair: KeyPair,
      nextUpdate: LocalDate,
      legalHeader: String = "Kom ihåg att du aldrig får snyta dig i mattan!",
      no: Int = 1,
  ): String = {
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
    makeBlob(blobKeypair, blobHeader, blobBody)
  }

  private def makeHttpServer(
      path: String,
      response: String,
  ): (Server, String, X509Certificate) =
    makeHttpServer(
      Map(path -> (200, response.getBytes(StandardCharsets.UTF_8)))
    )
  private def makeHttpServer(
      path: String,
      response: Array[Byte],
  ): (Server, String, X509Certificate) =
    makeHttpServer(Map(path -> (200, response)))
  private def makeHttpServer(
      responses: Map[String, (Int, Array[Byte])]
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
          case Some((status, responseBody)) => {
            response.getOutputStream.write(responseBody)
            response.setStatus(status)
          }
          case None => response.setStatus(404)
        }

        jettyRequest.setHandled(true)
      }
    })

    (server, s"https://localhost:${port}", tlsCert)
  }

  private def withEachLoadMethod(
      body: (FidoMetadataDownloader => MetadataBLOB) => Unit
  ): Unit = {
    describe("[using loadCachedBlob()]") {
      body(_.loadCachedBlob())
    }
    describe("[using refreshBlob()]") {
      body(_.refreshBlob())
    }
  }

  describe("§3.2. Metadata BLOB object processing rules") {
    withEachLoadMethod { load =>
      describe("1. Download and cache the root signing trust anchor from the respective MDS root location e.g. More information can be found at https://fidoalliance.org/metadata/") {
        it(
          "The trust root is downloaded and cached if there isn't a supplier-cached one."
        ) {
          val random = new SecureRandom()
          val trustRootDistinguishedName =
            s"CN=Test trust root ${random.nextInt(10000)}"
          val (trustRootCert, caKeypair, caName) =
            makeTrustRootCert(distinguishedName = trustRootDistinguishedName)
          val (blobCert, blobKeypair, _) = makeCert(caKeypair, caName)
          val blobJwt =
            makeBlob(List(blobCert), blobKeypair, LocalDate.now())
          val crls = List[CRL](
            TestAuthenticator.buildCrl(
              caName,
              caKeypair.getPrivate,
              "SHA256withECDSA",
              CertValidFrom,
              CertValidTo,
            )
          )

          var writtenCache: Option[ByteArray] = None

          val (server, serverUrl, httpsCert) =
            makeHttpServer("/trust-root.der", trustRootCert.getEncoded)
          startServer(server)

          val blob = load(
            FidoMetadataDownloader
              .builder()
              .expectLegalHeader(
                "Kom ihåg att du aldrig får snyta dig i mattan!"
              )
              .downloadTrustRoot(
                new URL(s"${serverUrl}/trust-root.der"),
                Set(
                  TestAuthenticator.sha256(
                    new ByteArray(trustRootCert.getEncoded)
                  )
                ).asJava,
              )
              .useTrustRootCache(
                () => Optional.empty(),
                newCache => {
                  writtenCache = Some(newCache)
                },
              )
              .useBlob(blobJwt)
              .clock(Clock.fixed(CertValidFrom, ZoneOffset.UTC))
              .useCrls(crls.asJava)
              .trustHttpsCerts(httpsCert)
              .build()
          )

          blob should not be null
          blob.getHeader.getX5c.get.asScala.last.getIssuerDN.getName should equal(
            trustRootDistinguishedName
          )
          writtenCache should equal(
            Some(new ByteArray(trustRootCert.getEncoded))
          )
        }

        it("The trust root is downloaded and cached if there's an expired one in supplier-cache.") {
          val random = new SecureRandom()

          val oldTrustRootDistinguishedName =
            s"CN=Test trust root ${random.nextInt(10000)}"
          val newTrustRootDistinguishedName =
            s"CN=Test trust root ${random.nextInt(10000) + 10000}"
          val (oldTrustRootCert, _, _) =
            makeTrustRootCert(
              distinguishedName = oldTrustRootDistinguishedName,
              validFrom = CertValidFrom.minusSeconds(600),
              validTo = CertValidFrom.minusSeconds(1),
            )
          val (newTrustRootCert, caKeypair, caName) =
            makeTrustRootCert(distinguishedName = newTrustRootDistinguishedName)

          val (blobCert, blobKeypair, _) = makeCert(caKeypair, caName)
          val blobJwt =
            makeBlob(List(blobCert), blobKeypair, LocalDate.now())
          val crls = List[CRL](
            TestAuthenticator.buildCrl(
              caName,
              caKeypair.getPrivate,
              "SHA256withECDSA",
              CertValidFrom,
              CertValidTo,
            )
          )

          var writtenCache: Option[ByteArray] = None

          val (server, serverUrl, httpsCert) =
            makeHttpServer("/trust-root.der", newTrustRootCert.getEncoded)
          startServer(server)

          val blob = load(
            FidoMetadataDownloader
              .builder()
              .expectLegalHeader(
                "Kom ihåg att du aldrig får snyta dig i mattan!"
              )
              .downloadTrustRoot(
                new URL(s"${serverUrl}/trust-root.der"),
                Set(
                  TestAuthenticator.sha256(
                    new ByteArray(newTrustRootCert.getEncoded)
                  )
                ).asJava,
              )
              .useTrustRootCache(
                () => Optional.of(new ByteArray(oldTrustRootCert.getEncoded)),
                newCache => {
                  writtenCache = Some(newCache)
                },
              )
              .useBlob(blobJwt)
              .clock(Clock.fixed(CertValidFrom, ZoneOffset.UTC))
              .useCrls(crls.asJava)
              .trustHttpsCerts(httpsCert)
              .build()
          )
          blob should not be null
          blob.getHeader.getX5c.get.asScala.last.getIssuerDN.getName should equal(
            newTrustRootDistinguishedName
          )
          writtenCache should equal(
            Some(new ByteArray(newTrustRootCert.getEncoded))
          )
        }

        it(
          "The trust root is not downloaded and not written to cache if there's a valid one in file cache."
        ) {
          val random = new SecureRandom()
          val trustRootDistinguishedName =
            s"CN=Test trust root ${random.nextInt(10000)}"
          val (trustRootCert, caKeypair, caName) =
            makeTrustRootCert(distinguishedName = trustRootDistinguishedName)
          val (blobCert, blobKeypair, _) = makeCert(caKeypair, caName)
          val blobJwt =
            makeBlob(List(blobCert), blobKeypair, LocalDate.now())
          val crls = List[CRL](
            TestAuthenticator.buildCrl(
              caName,
              caKeypair.getPrivate,
              "SHA256withECDSA",
              CertValidFrom,
              CertValidTo,
            )
          )

          val cacheFile = File.createTempFile(
            s"${getClass.getCanonicalName}_test_cache_",
            ".tmp",
          )
          val f = new FileOutputStream(cacheFile)
          f.write(trustRootCert.getEncoded)
          f.close()
          cacheFile.deleteOnExit()
          cacheFile.setLastModified(
            cacheFile.lastModified() - 1000
          ) // Set mtime in the past to ensure any write will change it
          val initialModTime = cacheFile.lastModified

          val blob = load(
            FidoMetadataDownloader
              .builder()
              .expectLegalHeader(
                "Kom ihåg att du aldrig får snyta dig i mattan!"
              )
              .downloadTrustRoot(
                new URL("https://localhost:12345/nonexistent.dev.null"),
                Set(
                  TestAuthenticator.sha256(
                    new ByteArray(trustRootCert.getEncoded)
                  )
                ).asJava,
              )
              .useTrustRootCacheFile(cacheFile)
              .useBlob(blobJwt)
              .clock(Clock.fixed(CertValidFrom, ZoneOffset.UTC))
              .useCrls(crls.asJava)
              .build()
          )
          blob should not be null
          blob.getHeader.getX5c.get.asScala.last.getIssuerDN.getName should equal(
            trustRootDistinguishedName
          )
          cacheFile.lastModified should equal(initialModTime)
        }

        it(
          "The trust root is downloaded and cached if there isn't a file-cached one."
        ) {
          val random = new SecureRandom()
          val trustRootDistinguishedName =
            s"CN=Test trust root ${random.nextInt(10000)}"
          val (trustRootCert, caKeypair, caName) =
            makeTrustRootCert(distinguishedName = trustRootDistinguishedName)
          val (blobCert, blobKeypair, _) = makeCert(caKeypair, caName)
          val blobJwt =
            makeBlob(List(blobCert), blobKeypair, LocalDate.now())
          val crls = List[CRL](
            TestAuthenticator.buildCrl(
              caName,
              caKeypair.getPrivate,
              "SHA256withECDSA",
              CertValidFrom,
              CertValidTo,
            )
          )

          val (server, serverUrl, httpsCert) =
            makeHttpServer("/trust-root.der", trustRootCert.getEncoded)
          startServer(server)

          val cacheFile = File.createTempFile(
            s"${getClass.getCanonicalName}_test_cache_",
            ".tmp",
          )
          cacheFile.delete()
          cacheFile.deleteOnExit()

          val blob = load(
            FidoMetadataDownloader
              .builder()
              .expectLegalHeader(
                "Kom ihåg att du aldrig får snyta dig i mattan!"
              )
              .downloadTrustRoot(
                new URL(s"${serverUrl}/trust-root.der"),
                Set(
                  TestAuthenticator.sha256(
                    new ByteArray(trustRootCert.getEncoded)
                  )
                ).asJava,
              )
              .useTrustRootCacheFile(cacheFile)
              .useBlob(blobJwt)
              .clock(Clock.fixed(CertValidFrom, ZoneOffset.UTC))
              .useCrls(crls.asJava)
              .trustHttpsCerts(httpsCert)
              .build()
          )
          blob should not be null
          blob.getHeader.getX5c.get.asScala.last.getIssuerDN.getName should equal(
            trustRootDistinguishedName
          )
          cacheFile.exists() should be(true)
          BinaryUtil.readAll(new FileInputStream(cacheFile)) should equal(
            trustRootCert.getEncoded
          )
        }

        it("The trust root is downloaded and cached if there's an expired one in file cache.") {
          val random = new SecureRandom()

          val oldTrustRootDistinguishedName =
            s"CN=Test trust root ${random.nextInt(10000)}"
          val newTrustRootDistinguishedName =
            s"CN=Test trust root ${random.nextInt(10000) + 10000}"
          val (oldTrustRootCert, _, _) =
            makeTrustRootCert(
              distinguishedName = oldTrustRootDistinguishedName,
              validFrom = CertValidFrom.minusSeconds(600),
              validTo = CertValidFrom.minusSeconds(1),
            )
          val (newTrustRootCert, caKeypair, caName) =
            makeTrustRootCert(distinguishedName = newTrustRootDistinguishedName)

          val (blobCert, blobKeypair, _) = makeCert(caKeypair, caName)
          val blobJwt =
            makeBlob(List(blobCert), blobKeypair, LocalDate.now())
          val crls = List[CRL](
            TestAuthenticator.buildCrl(
              caName,
              caKeypair.getPrivate,
              "SHA256withECDSA",
              CertValidFrom,
              CertValidTo,
            )
          )

          val (server, serverUrl, httpsCert) =
            makeHttpServer("/trust-root.der", newTrustRootCert.getEncoded)
          startServer(server)

          val cacheFile = File.createTempFile(
            s"${getClass.getCanonicalName}_test_cache_",
            ".tmp",
          )
          val f = new FileOutputStream(cacheFile)
          f.write(oldTrustRootCert.getEncoded)
          f.close()
          cacheFile.deleteOnExit()

          val blob = load(
            FidoMetadataDownloader
              .builder()
              .expectLegalHeader(
                "Kom ihåg att du aldrig får snyta dig i mattan!"
              )
              .downloadTrustRoot(
                new URL(s"${serverUrl}/trust-root.der"),
                Set(
                  TestAuthenticator.sha256(
                    new ByteArray(newTrustRootCert.getEncoded)
                  )
                ).asJava,
              )
              .useTrustRootCacheFile(cacheFile)
              .useBlob(blobJwt)
              .clock(Clock.fixed(CertValidFrom, ZoneOffset.UTC))
              .useCrls(crls.asJava)
              .trustHttpsCerts(httpsCert)
              .build()
          )
          blob should not be null
          blob.getHeader.getX5c.get.asScala.last.getIssuerDN.getName should equal(
            newTrustRootDistinguishedName
          )
          cacheFile.exists() should be(true)
          BinaryUtil.readAll(new FileInputStream(cacheFile)) should equal(
            newTrustRootCert.getEncoded
          )
        }

        it("The trust root is not downloaded if there's a valid one in supplier-cache.") {
          val random = new SecureRandom()
          val trustRootDistinguishedName =
            s"CN=Test trust root ${random.nextInt(10000)}"
          val (trustRootCert, caKeypair, caName) =
            makeTrustRootCert(distinguishedName = trustRootDistinguishedName)
          val (blobCert, blobKeypair, _) = makeCert(caKeypair, caName)
          val blobJwt =
            makeBlob(List(blobCert), blobKeypair, LocalDate.now())
          val crls = List[CRL](
            TestAuthenticator.buildCrl(
              caName,
              caKeypair.getPrivate,
              "SHA256withECDSA",
              CertValidFrom,
              CertValidTo,
            )
          )

          var writtenCache: Option[ByteArray] = None

          val blob = load(
            FidoMetadataDownloader
              .builder()
              .expectLegalHeader(
                "Kom ihåg att du aldrig får snyta dig i mattan!"
              )
              .downloadTrustRoot(
                new URL("https://localhost:12345/nonexistent.dev.null"),
                Set(
                  TestAuthenticator.sha256(
                    new ByteArray(trustRootCert.getEncoded)
                  )
                ).asJava,
              )
              .useTrustRootCache(
                () => Optional.of(new ByteArray(trustRootCert.getEncoded)),
                newCache => {
                  writtenCache = Some(newCache)
                },
              )
              .useBlob(blobJwt)
              .clock(Clock.fixed(CertValidFrom, ZoneOffset.UTC))
              .useCrls(crls.asJava)
              .build()
          )
          blob should not be null
          blob.getHeader.getX5c.get.asScala.last.getIssuerDN.getName should equal(
            trustRootDistinguishedName
          )
          writtenCache should equal(None)
        }

        it("The downloaded trust root cert must match one of the expected SHA256 hashes.") {
          val (trustRootCert, caKeypair, caName) = makeTrustRootCert()
          val (blobCert, blobKeypair, _) = makeCert(caKeypair, caName)
          val blobJwt = makeBlob(List(blobCert), blobKeypair, LocalDate.now())
          val crls = List[CRL](
            TestAuthenticator.buildCrl(
              caName,
              caKeypair.getPrivate,
              "SHA256withECDSA",
              CertValidFrom,
              CertValidTo,
            )
          )

          val (server, serverUrl, httpsCert) =
            makeHttpServer("/trust-root.der", trustRootCert.getEncoded)
          startServer(server)

          def testWithHashes(hashes: Set[ByteArray]): MetadataBLOB = {
            load(
              FidoMetadataDownloader
                .builder()
                .expectLegalHeader(
                  "Kom ihåg att du aldrig får snyta dig i mattan!"
                )
                .downloadTrustRoot(
                  new URL(s"${serverUrl}/trust-root.der"),
                  hashes.asJava,
                )
                .useTrustRootCache(() => Optional.empty(), _ => {})
                .useBlob(blobJwt)
                .useCrls(crls.asJava)
                .trustHttpsCerts(httpsCert)
                .clock(Clock.fixed(CertValidFrom, ZoneOffset.UTC))
                .build()
            )
          }

          val goodHash =
            TestAuthenticator.sha256(new ByteArray(trustRootCert.getEncoded))
          val badHash = TestAuthenticator.sha256(goodHash)

          a[DigestException] should be thrownBy {
            testWithHashes(Set(badHash))
          }
          testWithHashes(Set(goodHash)) should not be null
          testWithHashes(Set(badHash, goodHash)) should not be null
        }

        it("The cached trust root cert must match one of the expected SHA256 hashes.") {
          val (cachedTrustRootCert, cachedCaKeypair, cachedCaName) =
            makeTrustRootCert()
          val (cachedRootBlobCert, cachedRootBlobKeypair, _) =
            makeCert(cachedCaKeypair, cachedCaName)
          val cachedRootBlobJwt = makeBlob(
            List(cachedRootBlobCert),
            cachedRootBlobKeypair,
            LocalDate.now(),
          )
          val cachedRootCrls = List[CRL](
            TestAuthenticator.buildCrl(
              cachedCaName,
              cachedCaKeypair.getPrivate,
              "SHA256withECDSA",
              CertValidFrom,
              CertValidTo,
            )
          )

          val (downloadedTrustRootCert, downloadedCaKeypair, downloadedCaName) =
            makeTrustRootCert()
          val (downloadedRootBlobCert, downloadedRootBlobKeypair, _) =
            makeCert(downloadedCaKeypair, downloadedCaName)
          val downloadedRootBlobJwt = makeBlob(
            List(downloadedRootBlobCert),
            downloadedRootBlobKeypair,
            LocalDate.now(),
          )
          val downloadedRootCrls = List[CRL](
            TestAuthenticator.buildCrl(
              downloadedCaName,
              downloadedCaKeypair.getPrivate,
              "SHA256withECDSA",
              CertValidFrom,
              CertValidTo,
            )
          )

          val (server, serverUrl, httpsCert) =
            makeHttpServer(
              "/trust-root.der",
              downloadedTrustRootCert.getEncoded,
            )
          startServer(server)

          def testWithHashes(
              hashes: Set[ByteArray],
              blobJwt: String,
              crls: List[CRL],
          ): (MetadataBLOB, Option[ByteArray]) = {
            var writtenCache: Option[ByteArray] = None

            val blob = load(
              FidoMetadataDownloader
                .builder()
                .expectLegalHeader(
                  "Kom ihåg att du aldrig får snyta dig i mattan!"
                )
                .downloadTrustRoot(
                  new URL(s"${serverUrl}/trust-root.der"),
                  hashes.asJava,
                )
                .useTrustRootCache(
                  () =>
                    Optional.of(new ByteArray(cachedTrustRootCert.getEncoded)),
                  downloaded => { writtenCache = Some(downloaded) },
                )
                .useBlob(blobJwt)
                .useCrls(crls.asJava)
                .trustHttpsCerts(httpsCert)
                .clock(Clock.fixed(CertValidFrom, ZoneOffset.UTC))
                .build()
            )

            (blob, writtenCache)
          }

          {
            val (blob, writtenCache) = testWithHashes(
              Set(
                TestAuthenticator.sha256(
                  new ByteArray(cachedTrustRootCert.getEncoded)
                )
              ),
              cachedRootBlobJwt,
              cachedRootCrls,
            )
            blob should not be null
            writtenCache should be(None)
          }

          {
            val (blob, writtenCache) = testWithHashes(
              Set(
                TestAuthenticator.sha256(
                  new ByteArray(downloadedTrustRootCert.getEncoded)
                )
              ),
              downloadedRootBlobJwt,
              downloadedRootCrls,
            )
            blob should not be null
            writtenCache should be(
              Some(new ByteArray(downloadedTrustRootCert.getEncoded))
            )
          }
        }
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
            load(
              FidoMetadataDownloader
                .builder()
                .expectLegalHeader(
                  "Kom ihåg att du aldrig får snyta dig i mattan!"
                )
                .useTrustRoot(trustRootCert)
                .useBlob(blobJwt)
                .clock(Clock.fixed(CertValidFrom, ZoneOffset.UTC))
                .build()
            )
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
              CertValidFrom,
              CertValidTo,
            )
          )

          val blob = load(
            FidoMetadataDownloader
              .builder()
              .expectLegalHeader(
                "Kom ihåg att du aldrig får snyta dig i mattan!"
              )
              .useTrustRoot(trustRootCert)
              .useBlob(blobJwt)
              .useCrls(crls.asJava)
              .clock(Clock.fixed(CertValidFrom, ZoneOffset.UTC))
              .build()
          )
          blob should not be null
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
              load(
                FidoMetadataDownloader
                  .builder()
                  .expectLegalHeader(
                    "Kom ihåg att du aldrig får snyta dig i mattan!"
                  )
                  .useTrustRoot(trustRootCert)
                  .useBlob(blobJwt)
                  .clock(Clock.fixed(CertValidFrom, ZoneOffset.UTC))
                  .build()
              )
            }
            thrown.getReason should equal(
              BasicReason.UNDETERMINED_REVOCATION_STATUS
            )

            val rootCrl = TestAuthenticator.buildCrl(
              caName,
              caKeypair.getPrivate,
              "SHA256withECDSA",
              CertValidFrom,
              CertValidTo,
            )

            val thrown2 = the[CertPathValidatorException] thrownBy {
              load(
                FidoMetadataDownloader
                  .builder()
                  .expectLegalHeader(
                    "Kom ihåg att du aldrig får snyta dig i mattan!"
                  )
                  .useTrustRoot(trustRootCert)
                  .useBlob(blobJwt)
                  .clock(Clock.fixed(CertValidFrom, ZoneOffset.UTC))
                  .useCrls(List[CRL](rootCrl).asJava)
                  .build()
              )
            }
            thrown2.getReason should equal(
              BasicReason.UNDETERMINED_REVOCATION_STATUS
            )

            val intermediateCrl = TestAuthenticator.buildCrl(
              intermediateName,
              intermediateKeypair.getPrivate,
              "SHA256withECDSA",
              CertValidFrom,
              CertValidTo,
            )

            val thrown3 = the[CertPathValidatorException] thrownBy {
              load(
                FidoMetadataDownloader
                  .builder()
                  .expectLegalHeader(
                    "Kom ihåg att du aldrig får snyta dig i mattan!"
                  )
                  .useTrustRoot(trustRootCert)
                  .useBlob(blobJwt)
                  .clock(Clock.fixed(CertValidFrom, ZoneOffset.UTC))
                  .useCrls(List[CRL](intermediateCrl).asJava)
                  .build()
              )
            }
            thrown3.getReason should equal(
              BasicReason.UNDETERMINED_REVOCATION_STATUS
            )

            val blob = load(
              FidoMetadataDownloader
                .builder()
                .expectLegalHeader(
                  "Kom ihåg att du aldrig får snyta dig i mattan!"
                )
                .useTrustRoot(trustRootCert)
                .useBlob(blobJwt)
                .useCrls(List[CRL](rootCrl, intermediateCrl).asJava)
                .clock(Clock.fixed(CertValidFrom, ZoneOffset.UTC))
                .build()
            )
            blob should not be null
          }

          it("can revoke downstream certificates too.") {
            val rootCrl = TestAuthenticator.buildCrl(
              caName,
              caKeypair.getPrivate,
              "SHA256withECDSA",
              CertValidFrom,
              CertValidTo,
            )
            val intermediateCrl = TestAuthenticator.buildCrl(
              intermediateName,
              intermediateKeypair.getPrivate,
              "SHA256withECDSA",
              CertValidFrom,
              CertValidTo,
              revoked = Set(blobCert),
            )
            val crls = List(rootCrl, intermediateCrl)

            val thrown = the[CertPathValidatorException] thrownBy {
              load(
                FidoMetadataDownloader
                  .builder()
                  .expectLegalHeader(
                    "Kom ihåg att du aldrig får snyta dig i mattan!"
                  )
                  .useTrustRoot(trustRootCert)
                  .useBlob(blobJwt)
                  .useCrls(crls.asJava)
                  .clock(
                    Clock.fixed(CertValidFrom.plusSeconds(1), ZoneOffset.UTC)
                  )
                  .build()
              )
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
              CertValidFrom,
              CertValidTo,
            )
          )

          val (server, serverUrl, httpsCert) =
            makeHttpServer("/blob.jwt", blobJwt)
          startServer(server)

          val blob = load(
            FidoMetadataDownloader
              .builder()
              .expectLegalHeader(blobLegalHeader)
              .useTrustRoot(trustRootCert)
              .downloadBlob(new URL(s"${serverUrl}/blob.jwt"))
              .useBlobCache(() => Optional.empty(), _ => {})
              .clock(Clock.fixed(CertValidFrom, ZoneOffset.UTC))
              .useCrls(crls.asJava)
              .trustHttpsCerts(httpsCert)
              .build()
          ).getPayload
          blob should not be null
          blob.getLegalHeader should equal(blobLegalHeader)
          blob.getNo should equal(blobNo)
        }

        it("The cache is used if the BLOB download fails.") {
          val oldBlobNo = 1
          val newBlobNo = 2

          val (trustRootCert, caKeypair, caName) = makeTrustRootCert()
          val (blobCert, blobKeypair, _) = makeCert(caKeypair, caName)
          val oldBlobJwt =
            makeBlob(
              List(blobCert),
              blobKeypair,
              CertValidFrom.atOffset(ZoneOffset.UTC).toLocalDate,
              no = oldBlobNo,
            )
          val newBlobJwt =
            makeBlob(
              List(blobCert),
              blobKeypair,
              CertValidTo.atOffset(ZoneOffset.UTC).toLocalDate,
              no = newBlobNo,
            )
          val crls = List[CRL](
            TestAuthenticator.buildCrl(
              caName,
              caKeypair.getPrivate,
              "SHA256withECDSA",
              CertValidFrom,
              CertValidTo,
            )
          )

          val (server, serverUrl, httpsCert) =
            makeHttpServer(
              Map(
                "/blob.jwt" -> (HttpStatus.TOO_MANY_REQUESTS_429, newBlobJwt
                  .getBytes(StandardCharsets.UTF_8))
              )
            )
          startServer(server)

          val blob = load(
            FidoMetadataDownloader
              .builder()
              .expectLegalHeader(
                "Kom ihåg att du aldrig får snyta dig i mattan!"
              )
              .useTrustRoot(trustRootCert)
              .downloadBlob(new URL(s"${serverUrl}/blob.jwt"))
              .useBlobCache(
                () =>
                  Optional.of(
                    new ByteArray(oldBlobJwt.getBytes(StandardCharsets.UTF_8))
                  ),
                _ => {},
              )
              .clock(Clock.fixed(CertValidFrom, ZoneOffset.UTC))
              .useCrls(crls.asJava)
              .trustHttpsCerts(httpsCert)
              .build()
          ).getPayload
          blob should not be null
          blob.getNo should equal(oldBlobNo)
        }
      }

      describe("4. If the x5u attribute is present in the JWT Header, then:") {

        describe("1. The FIDO Server MUST verify that the URL specified by the x5u attribute has the same web-origin as the URL used to download the metadata BLOB from. The FIDO Server SHOULD ignore the file if the web-origin differs (in order to prevent loading objects from arbitrary sites).") {
          it("x5u on a different host is rejected.") {
            val (trustRootCert, caKeypair, caName) = makeTrustRootCert()
            val (blobCert, blobKeypair, _) = makeCert(caKeypair, caName)

            val certChain = List(blobCert)
            val certChainPem = certChain
              .map(cert => new ByteArray(cert.getEncoded).getBase64)
              .mkString(
                "-----BEGIN CERTIFICATE-----\n",
                "\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\n",
                "\n-----END CERTIFICATE-----",
              )

            val blobJwt =
              makeBlob(
                blobKeypair,
                s"""{"alg":"ES256","x5u": "https://localhost:8444/chain.pem"}""",
                s"""{
              "legalHeader": "Kom ihåg att du aldrig får snyta dig i mattan!",
              "no": 1,
              "nextUpdate": "2022-01-19",
              "entries": []
            }""",
              )

            val (server, _, httpsCert) =
              makeHttpServer(
                Map(
                  "/chain.pem" -> (200, certChainPem.getBytes(
                    StandardCharsets.UTF_8
                  )),
                  "/blob.jwt" -> (200, blobJwt.getBytes(StandardCharsets.UTF_8)),
                )
              )
            startServer(server)

            val crls = List[CRL](
              TestAuthenticator.buildCrl(
                caName,
                caKeypair.getPrivate,
                "SHA256withECDSA",
                CertValidFrom,
                CertValidTo,
              )
            )

            val thrown = the[IllegalArgumentException] thrownBy {
              load(
                FidoMetadataDownloader
                  .builder()
                  .expectLegalHeader(
                    "Kom ihåg att du aldrig får snyta dig i mattan!"
                  )
                  .useTrustRoot(trustRootCert)
                  .downloadBlob(new URL("https://localhost:8443/blob.jwt"))
                  .useBlobCache(() => Optional.empty(), _ => {})
                  .useCrls(crls.asJava)
                  .trustHttpsCerts(httpsCert)
                  .build()
              )
            }
            thrown should not be null
          }
        }

        describe("2. The FIDO Server MUST download the certificate (chain) from the URL specified by the x5u attribute [JWS]. The certificate chain MUST be verified to properly chain to the metadata BLOB signing trust anchor according to [RFC5280]. All certificates in the chain MUST be checked for revocation according to [RFC5280].") {
          it("x5u with one cert is accepted.") {
            val (trustRootCert, caKeypair, caName) = makeTrustRootCert()
            val (blobCert, blobKeypair, _) = makeCert(caKeypair, caName)

            val certChain = List(blobCert)
            val certChainPem = certChain
              .map(cert => new ByteArray(cert.getEncoded).getBase64)
              .mkString(
                "-----BEGIN CERTIFICATE-----\n",
                "\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\n",
                "\n-----END CERTIFICATE-----",
              )

            val (server, serverUrl, httpsCert) =
              makeHttpServer("/chain.pem", certChainPem)
            startServer(server)

            val blobJwt =
              makeBlob(
                blobKeypair,
                s"""{"alg":"ES256","x5u": "${serverUrl}/chain.pem"}""",
                s"""{
              "legalHeader": "Kom ihåg att du aldrig får snyta dig i mattan!",
              "no": 1,
              "nextUpdate": "2022-01-19",
              "entries": []
            }""",
              )
            val crls = List[CRL](
              TestAuthenticator.buildCrl(
                caName,
                caKeypair.getPrivate,
                "SHA256withECDSA",
                CertValidFrom,
                CertValidTo,
              )
            )

            val blob = load(
              FidoMetadataDownloader
                .builder()
                .expectLegalHeader(
                  "Kom ihåg att du aldrig får snyta dig i mattan!"
                )
                .useTrustRoot(trustRootCert)
                .useBlob(blobJwt)
                .useCrls(crls.asJava)
                .trustHttpsCerts(httpsCert)
                .clock(Clock.fixed(CertValidFrom, ZoneOffset.UTC))
                .build()
            )
            blob should not be null
          }

          it("x5u with an unknown trust anchor is rejected.") {
            val (trustRootCert, caKeypair, caName) = makeTrustRootCert()
            val (_, untrustedCaKeypair, untrustedCaName) = makeTrustRootCert()
            val (blobCert, blobKeypair, _) =
              makeCert(untrustedCaKeypair, untrustedCaName)

            val certChain = List(blobCert)
            val certChainPem = certChain
              .map(cert => new ByteArray(cert.getEncoded).getBase64)
              .mkString(
                "-----BEGIN CERTIFICATE-----\n",
                "\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\n",
                "\n-----END CERTIFICATE-----",
              )

            val (server, serverUrl, httpsCert) =
              makeHttpServer("/chain.pem", certChainPem)
            startServer(server)

            val blobJwt =
              makeBlob(
                blobKeypair,
                s"""{"alg":"ES256","x5u": "${serverUrl}/chain.pem"}""",
                s"""{
              "legalHeader": "Kom ihåg att du aldrig får snyta dig i mattan!",
              "no": 1,
              "nextUpdate": "2022-01-19",
              "entries": []
            }""",
              )
            val crls = List[CRL](
              TestAuthenticator.buildCrl(
                caName,
                caKeypair.getPrivate,
                "SHA256withECDSA",
                CertValidFrom,
                CertValidTo,
              )
            )

            val thrown = the[CertPathValidatorException] thrownBy {
              load(
                FidoMetadataDownloader
                  .builder()
                  .expectLegalHeader(
                    "Kom ihåg att du aldrig får snyta dig i mattan!"
                  )
                  .useTrustRoot(trustRootCert)
                  .useBlob(blobJwt)
                  .useCrls(crls.asJava)
                  .trustHttpsCerts(httpsCert)
                  .clock(Clock.fixed(CertValidFrom, ZoneOffset.UTC))
                  .build()
              )
            }
            thrown should not be null
            thrown.getReason should be(
              CertPathValidatorException.BasicReason.INVALID_SIGNATURE
            )
          }

          it("x5u with three certs requires a CRL for each CA certificate.") {
            val (trustRootCert, caKeypair, caName) = makeTrustRootCert()
            val certChain = makeCertChain(caKeypair, caName, 3)
            certChain.length should be(3)
            val certChainPem = certChain
              .map({
                case (cert, _, _) => new ByteArray(cert.getEncoded).getBase64
              })
              .mkString(
                "-----BEGIN CERTIFICATE-----\n",
                "\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\n",
                "\n-----END CERTIFICATE-----",
              )

            val crls =
              (certChain.tail :+ (trustRootCert, caKeypair, caName)).map({
                case (_, keypair, name) =>
                  TestAuthenticator.buildCrl(
                    name,
                    keypair.getPrivate,
                    "SHA256withECDSA",
                    CertValidFrom,
                    CertValidTo,
                  )
              })

            val (server, serverUrl, httpsCert) =
              makeHttpServer("/chain.pem", certChainPem)
            startServer(server)

            val blobJwt =
              makeBlob(
                certChain.head._2,
                s"""{"alg":"ES256","x5u": "${serverUrl}/chain.pem"}""",
                s"""{
              "legalHeader": "Kom ihåg att du aldrig får snyta dig i mattan!",
              "no": 1,
              "nextUpdate": "2022-01-19",
              "entries": []
            }""",
              )

            val clock = Clock.fixed(CertValidFrom, ZoneOffset.UTC)

            val blob = load(
              FidoMetadataDownloader
                .builder()
                .expectLegalHeader(
                  "Kom ihåg att du aldrig får snyta dig i mattan!"
                )
                .useTrustRoot(trustRootCert)
                .useBlob(blobJwt)
                .useCrls(crls.asJava)
                .trustHttpsCerts(httpsCert)
                .clock(clock)
                .build()
            )
            blob should not be null

            for { i <- certChain.indices } {
              val splicedCrls = crls.take(i) ++ crls.drop(i + 1)
              splicedCrls.length should be(crls.length - 1)
              val thrown = the[CertPathValidatorException] thrownBy {
                load(
                  FidoMetadataDownloader
                    .builder()
                    .expectLegalHeader(
                      "Kom ihåg att du aldrig får snyta dig i mattan!"
                    )
                    .useTrustRoot(trustRootCert)
                    .useBlob(blobJwt)
                    .useCrls(splicedCrls.asJava)
                    .trustHttpsCerts(httpsCert)
                    .clock(clock)
                    .build()
                )
              }
              thrown should not be null
              thrown.getReason should be(
                CertPathValidatorException.BasicReason.UNDETERMINED_REVOCATION_STATUS
              )
            }
          }
        }

        describe("3. The FIDO Server SHOULD ignore the file if the chain cannot be verified or if one of the chain certificates is revoked.") {
          it("Verification fails if explicitly given CRLs where a cert in the chain is revoked.") {
            val (trustRootCert, caKeypair, caName) = makeTrustRootCert()
            val certChain = makeCertChain(caKeypair, caName, 3)
            certChain.length should be(3)
            val certChainPem = certChain
              .map({
                case (cert, _, _) => new ByteArray(cert.getEncoded).getBase64
              })
              .mkString(
                "-----BEGIN CERTIFICATE-----\n",
                "\n-----END CERTIFICATE-----\n-----BEGIN CERTIFICATE-----\n",
                "\n-----END CERTIFICATE-----",
              )

            val crls =
              (certChain.tail :+ (trustRootCert, caKeypair, caName)).map({
                case (_, keypair, name) =>
                  TestAuthenticator.buildCrl(
                    name,
                    keypair.getPrivate,
                    "SHA256withECDSA",
                    CertValidFrom,
                    CertValidTo,
                  )
              })

            val (server, serverUrl, httpsCert) =
              makeHttpServer("/chain.pem", certChainPem)
            startServer(server)

            val blobJwt =
              makeBlob(
                certChain.head._2,
                s"""{"alg":"ES256","x5u": "${serverUrl}/chain.pem"}""",
                s"""{
              "legalHeader": "Kom ihåg att du aldrig får snyta dig i mattan!",
              "no": 1,
              "nextUpdate": "2022-01-19",
              "entries": []
            }""",
              )

            val clock =
              Clock.fixed(CertValidFrom.plusSeconds(1), ZoneOffset.UTC)

            val blob = load(
              FidoMetadataDownloader
                .builder()
                .expectLegalHeader(
                  "Kom ihåg att du aldrig får snyta dig i mattan!"
                )
                .useTrustRoot(trustRootCert)
                .useBlob(blobJwt)
                .useCrls(crls.asJava)
                .trustHttpsCerts(httpsCert)
                .clock(clock)
                .build()
            )
            blob should not be null

            for { i <- certChain.indices } {
              val crlsWithRevocation =
                crls.take(i) ++ crls.drop(i + 1) :+ TestAuthenticator.buildCrl(
                  certChain.lift(i + 1).map(_._3).getOrElse(caName),
                  certChain
                    .lift(i + 1)
                    .map(_._2)
                    .getOrElse(caKeypair)
                    .getPrivate,
                  "SHA256withECDSA",
                  CertValidFrom,
                  CertValidTo,
                  revoked = Set(certChain(i)._1),
                )
              crlsWithRevocation.length should equal(crls.length)
              val thrown = the[CertPathValidatorException] thrownBy {
                load(
                  FidoMetadataDownloader
                    .builder()
                    .expectLegalHeader(
                      "Kom ihåg att du aldrig får snyta dig i mattan!"
                    )
                    .useTrustRoot(trustRootCert)
                    .useBlob(blobJwt)
                    .useCrls(crlsWithRevocation.asJava)
                    .trustHttpsCerts(httpsCert)
                    .clock(clock)
                    .build()
                )
              }
              thrown should not be null
              thrown.getReason should be(BasicReason.REVOKED)
              thrown.getIndex should equal(i)
            }
          }
        }
      }

      describe("5. If the x5u attribute is missing, the chain should be retrieved from the x5c attribute. If that attribute is missing as well, Metadata BLOB signing trust anchor is considered the BLOB signing certificate chain.") {
        it("x5c with one cert is accepted.") {
          val (trustRootCert, caKeypair, caName) = makeTrustRootCert()
          val (blobCert, blobKeypair, _) = makeCert(caKeypair, caName)
          val certChain = List(blobCert)
          val certChainJson = certChain
            .map(cert => new ByteArray(cert.getEncoded).getBase64)
            .mkString("[\"", "\",\"", "\"]")
          val blobJwt =
            makeBlob(
              blobKeypair,
              s"""{"alg":"ES256","x5c": ${certChainJson}}""",
              s"""{
              "legalHeader": "Kom ihåg att du aldrig får snyta dig i mattan!",
              "no": 1,
              "nextUpdate": "2022-01-19",
              "entries": []
            }""",
            )
          val crls = List[CRL](
            TestAuthenticator.buildCrl(
              caName,
              caKeypair.getPrivate,
              "SHA256withECDSA",
              CertValidFrom,
              CertValidTo,
            )
          )

          val blob = load(
            FidoMetadataDownloader
              .builder()
              .expectLegalHeader(
                "Kom ihåg att du aldrig får snyta dig i mattan!"
              )
              .useTrustRoot(trustRootCert)
              .useBlob(blobJwt)
              .useCrls(crls.asJava)
              .clock(Clock.fixed(CertValidFrom, ZoneOffset.UTC))
              .build()
          )
          blob should not be null
        }

        it("x5c with three certs requires a CRL for each CA certificate.") {
          val (trustRootCert, caKeypair, caName) = makeTrustRootCert()
          val certChain = makeCertChain(caKeypair, caName, 3)
          certChain.length should be(3)
          val certChainJson = certChain
            .map({
              case (cert, _, _) => new ByteArray(cert.getEncoded).getBase64
            })
            .mkString("[\"", "\",\"", "\"]")

          val blobJwt =
            makeBlob(
              certChain.head._2,
              s"""{"alg":"ES256","x5c": ${certChainJson}}""",
              s"""{
              "legalHeader": "Kom ihåg att du aldrig får snyta dig i mattan!",
              "no": 1,
              "nextUpdate": "2022-01-19",
              "entries": []
            }""",
            )
          val crls =
            (certChain.tail :+ (trustRootCert, caKeypair, caName)).map({
              case (_, keypair, name) =>
                TestAuthenticator.buildCrl(
                  name,
                  keypair.getPrivate,
                  "SHA256withECDSA",
                  CertValidFrom,
                  CertValidTo,
                )
            })

          val clock = Clock.fixed(CertValidFrom, ZoneOffset.UTC)

          val blob = Try(
            load(
              FidoMetadataDownloader
                .builder()
                .expectLegalHeader(
                  "Kom ihåg att du aldrig får snyta dig i mattan!"
                )
                .useTrustRoot(trustRootCert)
                .useBlob(blobJwt)
                .useCrls(crls.asJava)
                .clock(clock)
                .build()
            )
          )
          blob should not be null
          blob shouldBe a[Success[_]]

          for { i <- certChain.indices } {
            val splicedCrls = crls.take(i) ++ crls.drop(i + 1)
            splicedCrls.length should be(crls.length - 1)
            val thrown = the[CertPathValidatorException] thrownBy {
              load(
                FidoMetadataDownloader
                  .builder()
                  .expectLegalHeader(
                    "Kom ihåg att du aldrig får snyta dig i mattan!"
                  )
                  .useTrustRoot(trustRootCert)
                  .useBlob(blobJwt)
                  .useCrls(splicedCrls.asJava)
                  .clock(clock)
                  .build()
              )
            }
            thrown should not be null
            thrown.getReason should be(
              CertPathValidatorException.BasicReason.UNDETERMINED_REVOCATION_STATUS
            )
          }
        }

        it("Missing x5c means the trust root cert is used as the signer.") {
          val (trustRootCert, caKeypair, caName) = makeTrustRootCert()
          val blobJwt =
            makeBlob(
              caKeypair,
              s"""{"alg":"ES256"}""",
              s"""{
              "legalHeader": "Kom ihåg att du aldrig får snyta dig i mattan!",
              "no": 1,
              "nextUpdate": "2022-01-19",
              "entries": []
            }""",
            )

          val crls = List(
            TestAuthenticator.buildCrl(
              caName,
              caKeypair.getPrivate,
              "SHA256withECDSA",
              CertValidFrom,
              CertValidTo,
            )
          )

          val blob = load(
            FidoMetadataDownloader
              .builder()
              .expectLegalHeader(
                "Kom ihåg att du aldrig får snyta dig i mattan!"
              )
              .useTrustRoot(trustRootCert)
              .useBlob(blobJwt)
              .useCrls(crls.asJava)
              .clock(Clock.fixed(CertValidFrom, ZoneOffset.UTC))
              .build()
          )
          blob should not be null
        }
      }

      describe("6. Verify the signature of the Metadata BLOB object using the BLOB signing certificate chain (as determined by the steps above). The FIDO Server SHOULD ignore the file if the signature is invalid. It SHOULD also ignore the file if its number (no) is less or equal to the number of the last Metadata BLOB object cached locally.") {
        it("Invalid signatures are detected.") {
          val (trustRootCert, caKeypair, caName) = makeTrustRootCert()
          val (blobCert, blobKeypair, _) = makeCert(caKeypair, caName)

          val validBlobJwt =
            makeBlob(List(blobCert), blobKeypair, LocalDate.parse("2022-01-19"))
          val crls = List(
            TestAuthenticator.buildCrl(
              caName,
              caKeypair.getPrivate,
              "SHA256withECDSA",
              CertValidFrom,
              CertValidTo,
            )
          )
          val badBlobJwt = validBlobJwt
            .split(raw"\.")
            .updated(
              1, {
                val json = JacksonCodecs.json()
                val badBlobBody = json
                  .readTree(
                    ByteArray
                      .fromBase64Url(validBlobJwt.split(raw"\.")(1))
                      .getBytes
                  )
                  .asInstanceOf[ObjectNode]
                badBlobBody.set("no", new IntNode(7))
                new ByteArray(
                  json
                    .writeValueAsString(badBlobBody)
                    .getBytes(StandardCharsets.UTF_8)
                ).getBase64
              },
            )
            .mkString(".")

          val thrown = the[FidoMetadataDownloaderException] thrownBy {
            load(
              FidoMetadataDownloader
                .builder()
                .expectLegalHeader(
                  "Kom ihåg att du aldrig får snyta dig i mattan!"
                )
                .useTrustRoot(trustRootCert)
                .useBlob(badBlobJwt)
                .useCrls(crls.asJava)
                .build()
            )
          }
          thrown.getReason should be(Reason.BAD_SIGNATURE)
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
              CertValidFrom.atOffset(ZoneOffset.UTC).toLocalDate,
              no = oldBlobNo,
            )
          val newBlobJwt =
            makeBlob(
              List(blobCert),
              blobKeypair,
              CertValidTo.atOffset(ZoneOffset.UTC).toLocalDate,
              no = newBlobNo,
            )
          val crls = List[CRL](
            TestAuthenticator.buildCrl(
              caName,
              caKeypair.getPrivate,
              "SHA256withECDSA",
              CertValidFrom,
              CertValidTo,
            )
          )

          val (server, serverUrl, httpsCert) =
            makeHttpServer("/blob.jwt", newBlobJwt)
          startServer(server)

          val blob = load(
            FidoMetadataDownloader
              .builder()
              .expectLegalHeader(
                "Kom ihåg att du aldrig får snyta dig i mattan!"
              )
              .useTrustRoot(trustRootCert)
              .downloadBlob(new URL(s"${serverUrl}/blob.jwt"))
              .useBlobCache(
                () =>
                  Optional.of(
                    new ByteArray(oldBlobJwt.getBytes(StandardCharsets.UTF_8))
                  ),
                _ => {},
              )
              .clock(Clock.fixed(CertValidFrom, ZoneOffset.UTC))
              .useCrls(crls.asJava)
              .trustHttpsCerts(httpsCert)
              .build()
          ).getPayload
          blob should not be null
          blob.getNo should equal(oldBlobNo)
        }

        it("A newly downloaded BLOB is disregarded if it has an invalid signature but the cached one has a valid signature.") {
          val oldBlobNo = 1
          val newBlobNo = 2

          val (trustRootCert, caKeypair, caName) = makeTrustRootCert()
          val (blobCert, blobKeypair, _) = makeCert(caKeypair, caName)
          val oldBlobJwt =
            makeBlob(
              List(blobCert),
              blobKeypair,
              CertValidFrom.atOffset(ZoneOffset.UTC).toLocalDate,
              no = oldBlobNo,
            )
          val newBlobJwt =
            makeBlob(
              List(blobCert),
              blobKeypair,
              CertValidTo.atOffset(ZoneOffset.UTC).toLocalDate,
              no = newBlobNo,
            )
          val crls = List[CRL](
            TestAuthenticator.buildCrl(
              caName,
              caKeypair.getPrivate,
              "SHA256withECDSA",
              CertValidFrom,
              CertValidTo,
            )
          )

          val badNewBlobJwt = newBlobJwt
            .split(raw"\.")
            .updated(
              1, {
                val json = JacksonCodecs.json()
                val badBlobBody = json
                  .readTree(
                    ByteArray
                      .fromBase64Url(newBlobJwt.split(raw"\.")(1))
                      .getBytes
                  )
                  .asInstanceOf[ObjectNode]
                badBlobBody.set("no", new IntNode(7))
                new ByteArray(
                  json
                    .writeValueAsString(badBlobBody)
                    .getBytes(StandardCharsets.UTF_8)
                ).getBase64
              },
            )
            .mkString(".")

          val (server, serverUrl, httpsCert) =
            makeHttpServer("/blob.jwt", badNewBlobJwt)
          startServer(server)

          val blob = load(
            FidoMetadataDownloader
              .builder()
              .expectLegalHeader(
                "Kom ihåg att du aldrig får snyta dig i mattan!"
              )
              .useTrustRoot(trustRootCert)
              .downloadBlob(new URL(s"${serverUrl}/blob.jwt"))
              .useBlobCache(
                () =>
                  Optional.of(
                    new ByteArray(oldBlobJwt.getBytes(StandardCharsets.UTF_8))
                  ),
                _ => {},
              )
              .clock(Clock.fixed(CertValidFrom, ZoneOffset.UTC))
              .useCrls(crls.asJava)
              .trustHttpsCerts(httpsCert)
              .build()
          ).getPayload
          blob should not be null
          blob.getNo should equal(oldBlobNo)
        }
      }

      describe("7. Write the verified object to a local cache as required.") {
        it("Cache consumer works.") {
          val (trustRootCert, caKeypair, caName) = makeTrustRootCert()
          val (blobCert, blobKeypair, _) = makeCert(caKeypair, caName)
          val blobJwt =
            makeBlob(List(blobCert), blobKeypair, LocalDate.parse("2022-01-19"))
          val crls = List(
            TestAuthenticator.buildCrl(
              caName,
              caKeypair.getPrivate,
              "SHA256withECDSA",
              CertValidFrom,
              CertValidTo,
            )
          )

          val (server, serverUrl, httpsCert) =
            makeHttpServer("/blob.jwt", blobJwt)
          startServer(server)

          var writtenCache: Option[ByteArray] = None

          val blob = load(
            FidoMetadataDownloader
              .builder()
              .expectLegalHeader(
                "Kom ihåg att du aldrig får snyta dig i mattan!"
              )
              .useTrustRoot(trustRootCert)
              .downloadBlob(new URL(s"${serverUrl}/blob.jwt"))
              .useBlobCache(
                () => Optional.empty(),
                cacheme => {
                  writtenCache = Some(cacheme)
                },
              )
              .clock(Clock.fixed(CertValidFrom, ZoneOffset.UTC))
              .useCrls(crls.asJava)
              .trustHttpsCerts(httpsCert)
              .build()
          ).getPayload
          blob should not be null
          writtenCache should equal(
            Some(new ByteArray(blobJwt.getBytes(StandardCharsets.UTF_8)))
          )
        }

        describe("File cache") {
          val (trustRootCert, caKeypair, caName) = makeTrustRootCert()
          val (blobCert, blobKeypair, _) = makeCert(caKeypair, caName)
          val blobJwt =
            makeBlob(
              List(blobCert),
              blobKeypair,
              LocalDate.parse("2022-01-19"),
              no = 2,
            )
          val oldBlobJwt =
            makeBlob(
              List(blobCert),
              blobKeypair,
              LocalDate.parse("2022-01-19"),
              no = 1,
            )
          val crls = List(
            TestAuthenticator.buildCrl(
              caName,
              caKeypair.getPrivate,
              "SHA256withECDSA",
              CertValidFrom,
              CertValidTo,
            )
          )

          it("is overwritten if it exists.") {
            val (server, serverUrl, httpsCert) =
              makeHttpServer("/blob.jwt", blobJwt)
            startServer(server)

            val cacheFile = File.createTempFile(
              s"${getClass.getCanonicalName}_test_cache_",
              ".tmp",
            )
            val f = new FileOutputStream(cacheFile)
            f.write(oldBlobJwt.getBytes(StandardCharsets.UTF_8))
            f.close()
            cacheFile.deleteOnExit()

            val blob = load(
              FidoMetadataDownloader
                .builder()
                .expectLegalHeader(
                  "Kom ihåg att du aldrig får snyta dig i mattan!"
                )
                .useTrustRoot(trustRootCert)
                .downloadBlob(new URL(s"${serverUrl}/blob.jwt"))
                .useBlobCacheFile(cacheFile)
                .clock(
                  Clock.fixed(
                    Instant.parse("2022-01-19T00:00:00Z"),
                    ZoneOffset.UTC,
                  )
                )
                .useCrls(crls.asJava)
                .trustHttpsCerts(httpsCert)
                .clock(Clock.fixed(CertValidFrom, ZoneOffset.UTC))
                .build()
            ).getPayload
            blob should not be null
            blob.getNo should be(2)
            cacheFile.exists() should be(true)
            BinaryUtil.readAll(new FileInputStream(cacheFile)) should equal(
              blobJwt.getBytes(StandardCharsets.UTF_8)
            )
          }

          it("is created if it does not exist.") {
            val (server, serverUrl, httpsCert) =
              makeHttpServer("/blob.jwt", blobJwt)
            startServer(server)

            val cacheFile = File.createTempFile(
              s"${getClass.getCanonicalName}_test_cache_",
              ".tmp",
            )
            cacheFile.delete()
            cacheFile.deleteOnExit()

            val blob = load(
              FidoMetadataDownloader
                .builder()
                .expectLegalHeader(
                  "Kom ihåg att du aldrig får snyta dig i mattan!"
                )
                .useTrustRoot(trustRootCert)
                .downloadBlob(new URL(s"${serverUrl}/blob.jwt"))
                .useBlobCacheFile(cacheFile)
                .clock(
                  Clock.fixed(
                    Instant.parse("2022-01-19T00:00:00Z"),
                    ZoneOffset.UTC,
                  )
                )
                .useCrls(crls.asJava)
                .trustHttpsCerts(httpsCert)
                .clock(Clock.fixed(CertValidFrom, ZoneOffset.UTC))
                .build()
            ).getPayload
            blob should not be null
            blob.getNo should be(2)
            cacheFile.exists() should be(true)
            BinaryUtil.readAll(new FileInputStream(cacheFile)) should equal(
              blobJwt.getBytes(StandardCharsets.UTF_8)
            )
          }

          it("is read from.") {
            val (server, serverUrl, httpsCert) =
              makeHttpServer("/blob.jwt", oldBlobJwt)
            startServer(server)

            val cacheFile = File.createTempFile(
              s"${getClass.getCanonicalName}_test_cache_",
              ".tmp",
            )
            cacheFile.deleteOnExit()
            val f = new FileOutputStream(cacheFile)
            f.write(blobJwt.getBytes(StandardCharsets.UTF_8))
            f.close()

            val blob = load(
              FidoMetadataDownloader
                .builder()
                .expectLegalHeader(
                  "Kom ihåg att du aldrig får snyta dig i mattan!"
                )
                .useTrustRoot(trustRootCert)
                .downloadBlob(new URL(s"${serverUrl}/blob.jwt"))
                .useBlobCacheFile(cacheFile)
                .clock(Clock.fixed(CertValidFrom, ZoneOffset.UTC))
                .useCrls(crls.asJava)
                .trustHttpsCerts(httpsCert)
                .build()
            ).getPayload
            blob should not be null
            blob.getNo should be(2)
          }
        }
      }

      describe("8. Iterate through the individual entries (of type MetadataBLOBPayloadEntry). For each entry:") {
        it("Nothing to test - see instead FidoMetadataService.") {}
      }
    }
  }

  describe("3. The FIDO Server MUST be able to download the latest metadata BLOB object from the well-known URL when appropriate, e.g. https://mds.fidoalliance.org/. The nextUpdate field of the Metadata BLOB specifies a date when the download SHOULD occur at latest.") {

    val oldBlobNo = 1
    val newBlobNo = 2

    val (trustRootCert, caKeypair, caName) = makeTrustRootCert()
    val (blobCert, blobKeypair, _) = makeCert(caKeypair, caName)
    val oldBlobJwt =
      makeBlob(
        List(blobCert),
        blobKeypair,
        CertValidTo.atOffset(ZoneOffset.UTC).toLocalDate,
        no = oldBlobNo,
      )
    val newBlobJwt =
      makeBlob(
        List(blobCert),
        blobKeypair,
        CertValidTo.atOffset(ZoneOffset.UTC).toLocalDate,
        no = newBlobNo,
      )
    val crls = List[CRL](
      TestAuthenticator.buildCrl(
        caName,
        caKeypair.getPrivate,
        "SHA256withECDSA",
        CertValidFrom,
        CertValidTo,
      )
    )

    val (server, serverUrl, httpsCert) =
      makeHttpServer("/blob.jwt", newBlobJwt)

    val downloader = FidoMetadataDownloader
      .builder()
      .expectLegalHeader(
        "Kom ihåg att du aldrig får snyta dig i mattan!"
      )
      .useTrustRoot(trustRootCert)
      .downloadBlob(new URL(s"${serverUrl}/blob.jwt"))
      .useBlobCache(
        () =>
          Optional.of(
            new ByteArray(oldBlobJwt.getBytes(StandardCharsets.UTF_8))
          ),
        _ => {},
      )
      .clock(Clock.fixed(CertValidFrom, ZoneOffset.UTC))
      .useCrls(crls.asJava)
      .trustHttpsCerts(httpsCert)
      .build()

    it(
      "[using loadCachedBlob] The BLOB is not downloaded if the cached one is not yet out of date."
    ) {
      startServer(server)
      val blob = downloader.loadCachedBlob().getPayload
      blob should not be null
      blob.getNo should equal(oldBlobNo)
    }

    it(
      "[using refreshBlob] The BLOB is always downloaded even if the cached one is not yet out of date."
    ) {
      startServer(server)
      val blob = downloader.refreshBlob().getPayload
      blob should not be null
      blob.getNo should equal(newBlobNo)
    }
  }

}
