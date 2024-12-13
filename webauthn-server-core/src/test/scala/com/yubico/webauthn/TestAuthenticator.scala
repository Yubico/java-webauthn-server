// Copyright (c) 2018, Yubico AB
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package com.yubico.webauthn

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.node.JsonNodeFactory
import com.fasterxml.jackson.databind.node.ObjectNode
import com.upokecenter.cbor.CBORObject
import com.yubico.internal.util.BinaryUtil
import com.yubico.internal.util.CertificateParser
import com.yubico.internal.util.JacksonCodecs
import com.yubico.webauthn.TpmAttestationStatementVerifier.Attributes
import com.yubico.webauthn.TpmAttestationStatementVerifier.TpmAlgAsym
import com.yubico.webauthn.TpmAttestationStatementVerifier.TpmAlgHash
import com.yubico.webauthn.TpmAttestationStatementVerifier.TpmRsaScheme
import com.yubico.webauthn.data.AuthenticatorAssertionResponse
import com.yubico.webauthn.data.AuthenticatorAttestationResponse
import com.yubico.webauthn.data.AuthenticatorData
import com.yubico.webauthn.data.AuthenticatorDataFlags
import com.yubico.webauthn.data.ByteArray
import com.yubico.webauthn.data.COSEAlgorithmIdentifier
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs
import com.yubico.webauthn.data.ClientRegistrationExtensionOutputs
import com.yubico.webauthn.data.PublicKeyCredential
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions
import org.bouncycastle.asn1.ASN1Encodable
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERTaggedObject
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.ReasonFlags
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.X509v2CRLBuilder
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX500NameUtil
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECNamedCurveSpec
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder

import java.io.ByteArrayInputStream
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.PublicKey
import java.security.SecureRandom
import java.security.Signature
import java.security.cert.CRL
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.time.Instant
import java.util.Date
import scala.jdk.CollectionConverters._
import scala.jdk.OptionConverters.RichOption
import scala.util.Try

object TestAuthenticator {

  private val random: SecureRandom = new SecureRandom()

  object Defaults {
    val aaguid: ByteArray = new ByteArray(
      Array(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15)
    )
    val challenge: ByteArray = new ByteArray(
      Array(0, 1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 16, 105, 121, 98, 91)
    )
    val credentialId: ByteArray = new ByteArray(
      ((0 to 31).toVector map { _.toByte }).toArray
    )
    val keyAlgorithm = COSEAlgorithmIdentifier.ES256
    val rpId = "localhost"
    val origin = "https://" + rpId
    object TokenBinding {
      val status = "supported"
      val id = None
    }

    val credentialKey: KeyPair = generateEcKeypair()

    val leafCertSubject: X500Name = new X500Name(
      "CN=Yubico WebAuthn unit tests, O=Yubico, OU=Authenticator Attestation, C=SE"
    )
    val caCertSubject: X500Name = new X500Name(
      "CN=Yubico WebAuthn unit tests CA, O=Yubico, OU=Authenticator Attestation, C=SE"
    )
    val certValidFrom: Instant = Instant.parse("2018-09-06T17:42:00Z")
    val certValidTo: Instant = certValidFrom.plusSeconds(7 * 24 * 3600)

    private var defaultKeypairs: Map[COSEAlgorithmIdentifier, KeyPair] =
      Map.empty
    def defaultKeypair(
        algorithm: COSEAlgorithmIdentifier = Defaults.keyAlgorithm
    ): KeyPair = {
      defaultKeypairs.get(algorithm) match {
        case Some(keypair) => keypair
        case None =>
          val keypair = generateKeypair(algorithm)
          defaultKeypairs = defaultKeypairs + (algorithm -> keypair)
          keypair
      }
    }
  }
  val RsaKeySizeBits = 2048
  val Es256PrimeModulus: BigInteger = new BigInteger(
    1,
    ByteArray
      .fromHex(
        "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"
      )
      .getBytes,
  )

  private def jsonFactory: JsonNodeFactory = JsonNodeFactory.instance
  private def jsonMap[V <: JsonNode](
      map: JsonNodeFactory => Map[String, V]
  ): ObjectNode =
    jsonFactory
      .objectNode()
      .setAll[ObjectNode](map.apply(jsonFactory).asJava)

  private def toBytes(s: String): ByteArray = new ByteArray(s.getBytes("UTF-8"))
  def sha256(s: String): ByteArray = sha256(toBytes(s))
  def sha256(b: ByteArray): ByteArray =
    new ByteArray(MessageDigest.getInstance("SHA-256").digest(b.getBytes))

  sealed trait AttestationMaker {
    val format: String
    def makeAttestationStatement(
        authDataBytes: ByteArray,
        clientDataJson: ByteArray,
    ): JsonNode
    def certChain: List[(X509Certificate, PrivateKey)] = Nil

    def makeAttestationObjectBytes(
        authDataBytes: ByteArray,
        clientDataJson: ByteArray,
    ): ByteArray = {
      val attObj = jsonMap { f =>
        Map(
          "authData" -> f.binaryNode(authDataBytes.getBytes),
          "fmt" -> f.textNode(format),
          "attStmt" -> makeAttestationStatement(authDataBytes, clientDataJson),
        )
      }
      new ByteArray(JacksonCodecs.cbor.writeValueAsBytes(attObj))
    }
  }
  object AttestationMaker {
    def default(): AttestationMaker =
      packed(AttestationSigner.selfsigned(COSEAlgorithmIdentifier.ES256))

    def packed(signer: AttestationSigner): AttestationMaker =
      new AttestationMaker {
        override val format = "packed"
        override def certChain = signer.certChain
        override def makeAttestationStatement(
            authDataBytes: ByteArray,
            clientDataJson: ByteArray,
        ): JsonNode =
          makePackedAttestationStatement(authDataBytes, clientDataJson, signer)
      }

    def fidoU2f(signer: AttestationSigner): AttestationMaker =
      new AttestationMaker {
        override val format = "fido-u2f"
        override def certChain = signer.certChain
        override def makeAttestationStatement(
            authDataBytes: ByteArray,
            clientDataJson: ByteArray,
        ): JsonNode =
          makeU2fAttestationStatement(authDataBytes, clientDataJson, signer)
      }

    def androidSafetynet(
        cert: AttestationCert,
        ctsProfileMatch: Boolean = true,
    ): AttestationMaker =
      new AttestationMaker {
        override val format = "android-safetynet"
        override def certChain = cert.certChain
        override def makeAttestationStatement(
            authDataBytes: ByteArray,
            clientDataJson: ByteArray,
        ): JsonNode =
          makeAndroidSafetynetAttestationStatement(
            authDataBytes,
            clientDataJson,
            cert,
            ctsProfileMatch = ctsProfileMatch,
          )
      }

    def apple(
        addNonceExtension: Boolean = true,
        nonceValue: Option[ByteArray] = None,
        certSubjectPublicKey: Option[PublicKey] = None,
    ): (AttestationMaker, X509Certificate, PrivateKey) = {
      val (caCert, caKey) =
        generateAttestationCertificate(
          COSEAlgorithmIdentifier.ES256,
          name = new X500Name(
            "CN=Yubico WebAuthn unit tests CA, O=Yubico, OU=Apple Attestation"
          ),
        )

      (
        new AttestationMaker {
          override val format = "apple"
          override def makeAttestationStatement(
              authDataBytes: ByteArray,
              clientDataJson: ByteArray,
          ): JsonNode =
            makeAppleAttestationStatement(
              caCert,
              caKey,
              authDataBytes,
              clientDataJson,
              addNonceExtension,
              nonceValue,
              certSubjectPublicKey,
            )
        },
        caCert,
        caKey,
      )
    }

    def tpm(
        cert: AttestationCert,
        ver: Option[String] = Some("2.0"),
        magic: ByteArray = TpmAttestationStatementVerifier.TPM_GENERATED_VALUE,
        `type`: ByteArray =
          TpmAttestationStatementVerifier.TPM_ST_ATTEST_CERTIFY,
        modifyAttestedName: ByteArray => ByteArray = an => an,
        overrideCosePubkey: Option[ByteArray] = None,
        attributes: Option[Long] = None,
        symmetric: Option[Int] = None,
        scheme: Option[Int] = None,
    ): AttestationMaker =
      new AttestationMaker {
        override val format = "tpm"
        override def certChain = cert.certChain
        override def makeAttestationStatement(
            authDataBytes: ByteArray,
            clientDataJson: ByteArray,
        ): JsonNode =
          makeTpmAttestationStatement(
            authDataBytes,
            clientDataJson,
            cert,
            ver = ver,
            magic = magic,
            `type` = `type`,
            modifyAttestedName = modifyAttestedName,
            overrideCosePubkey = overrideCosePubkey,
            attributes = attributes,
            symmetric = symmetric,
            scheme = scheme,
          )
      }

    def none(): AttestationMaker =
      new AttestationMaker {
        override val format = "none"
        override def certChain = Nil
        override def makeAttestationStatement(
            authDataBytes: ByteArray,
            clientDataJson: ByteArray,
        ): JsonNode =
          makeNoneAttestationStatement()
      }
  }

  sealed trait AttestationSigner {
    def key: PrivateKey; def alg: COSEAlgorithmIdentifier;
    def cert: X509Certificate
    def certChain: List[(X509Certificate, PrivateKey)]
  }

  case class SelfAttestation(keypair: KeyPair, alg: COSEAlgorithmIdentifier)
      extends AttestationSigner {
    override def key: PrivateKey = keypair.getPrivate
    override def cert: X509Certificate = {
      generateAttestationCertificate(alg = alg, keypair = Some(keypair))._1
    }
    override def certChain = Nil
  }

  case class AttestationCert(
      override val cert: X509Certificate,
      override val key: PrivateKey,
      alg: COSEAlgorithmIdentifier,
      override val certChain: List[(X509Certificate, PrivateKey)],
  ) extends AttestationSigner {
    def this(
        alg: COSEAlgorithmIdentifier,
        keypair: (X509Certificate, PrivateKey),
    ) = this(keypair._1, keypair._2, alg, Nil)
  }

  object AttestationSigner {
    def ca(
        alg: COSEAlgorithmIdentifier,
        aaguid: Option[ByteArray] = Some(Defaults.aaguid),
        certSubject: X500Name = Defaults.leafCertSubject,
        certExtensions: List[(String, Boolean, ASN1Encodable)] = Nil,
        validFrom: Instant = Defaults.certValidFrom,
        validTo: Instant = Defaults.certValidTo,
    ): AttestationCert = {
      val (caCert, caKey) =
        generateAttestationCaCertificate(
          signingAlg = alg,
          validFrom = validFrom,
          validTo = validTo,
        )
      val (cert, key) = generateAttestationCertificate(
        alg,
        caCertAndKey = Some((caCert, caKey)),
        name = certSubject,
        extensions = aaguid
          .map(aaguid =>
            (
              "1.3.6.1.4.1.45724.1.1.4",
              false,
              new DEROctetString(aaguid.getBytes),
            )
          )
          .toList ++ certExtensions,
        validFrom = validFrom,
        validTo = validTo,
      )
      AttestationCert(
        cert,
        key,
        alg,
        certChain = List((cert, key), (caCert, caKey)),
      )
    }

    def selfsigned(
        alg: COSEAlgorithmIdentifier,
        certSubject: X500Name = Defaults.leafCertSubject,
        issuerSubject: Option[X500Name] = None,
        certExtensions: List[(String, Boolean, ASN1Encodable)] = Nil,
        isCa: Boolean = false,
        validFrom: Instant = Defaults.certValidFrom,
        validTo: Instant = Defaults.certValidTo,
    ): AttestationCert = {
      val (cert, key) = generateAttestationCertificate(
        alg = alg,
        name = certSubject,
        issuerName = issuerSubject,
        extensions = certExtensions,
        isCa = isCa,
        validFrom = validFrom,
        validTo = validTo,
      )
      AttestationCert(cert, key, alg, certChain = List((cert, key)))
    }
  }

  def createAuthenticatorData(
      aaguid: ByteArray = Defaults.aaguid,
      authenticatorExtensions: Option[JsonNode] = None,
      credentialKeypair: Option[KeyPair] = None,
      keyAlgorithm: COSEAlgorithmIdentifier = Defaults.keyAlgorithm,
      flags: Option[AuthenticatorDataFlags] = None,
  ): (
      ByteArray,
      KeyPair,
  ) = {
    val keypair =
      credentialKeypair.getOrElse(generateKeypair(algorithm = keyAlgorithm))
    val publicKeyCose = keypair.getPublic match {
      case pub: ECPublicKey      => WebAuthnTestCodecs.ecPublicKeyToCose(pub)
      case pub: BCEdDSAPublicKey => WebAuthnTestCodecs.eddsaPublicKeyToCose(pub)
      case pub: RSAPublicKey =>
        WebAuthnTestCodecs.rsaPublicKeyToCose(pub, keyAlgorithm)
    }

    val authDataBytes: ByteArray = makeAuthDataBytes(
      rpId = Defaults.rpId,
      flags = flags,
      attestedCredentialDataBytes = Some(
        makeAttestedCredentialDataBytes(
          aaguid = aaguid,
          publicKeyCose = publicKeyCose,
        )
      ),
      extensionsCborBytes = authenticatorExtensions map (ext =>
        new ByteArray(JacksonCodecs.cbor().writeValueAsBytes(ext))
      ),
    )

    (
      authDataBytes,
      keypair,
    )
  }

  def createClientData(
      challenge: ByteArray = Defaults.challenge,
      clientData: Option[JsonNode] = None,
      origin: String = Defaults.origin,
      tokenBindingStatus: String = Defaults.TokenBinding.status,
      tokenBindingId: Option[String] = Defaults.TokenBinding.id,
  ): String =
    JacksonCodecs.json.writeValueAsString(clientData getOrElse {
      jsonMap {
        f =>
          Map(
            "challenge" -> f.textNode(challenge.getBase64Url),
            "origin" -> f.textNode(origin),
            "type" -> f.textNode("webauthn.create"),
            "tokenBinding" -> {
              val tokenBinding = f.objectNode()
              tokenBinding.set("status", f.textNode(tokenBindingStatus))
              tokenBindingId foreach { id =>
                tokenBinding.set("id", f.textNode(id))
              }
              tokenBinding
            },
          )
      }
    })

  def createCredential(
      authDataBytes: ByteArray,
      credentialKeypair: KeyPair,
      attestationMaker: AttestationMaker,
      clientDataJson: Option[String] = None,
      clientExtensions: ClientRegistrationExtensionOutputs =
        ClientRegistrationExtensionOutputs.builder().build(),
  ): (
      data.PublicKeyCredential[
        data.AuthenticatorAttestationResponse,
        ClientRegistrationExtensionOutputs,
      ],
      KeyPair,
      List[(X509Certificate, PrivateKey)],
  ) = {

    val clientDataJsonBytes = toBytes(
      clientDataJson.getOrElse(createClientData())
    )

    val attestationObjectBytes =
      attestationMaker.makeAttestationObjectBytes(
        authDataBytes,
        clientDataJsonBytes,
      )

    val response = AuthenticatorAttestationResponse
      .builder()
      .attestationObject(attestationObjectBytes)
      .clientDataJSON(clientDataJsonBytes)
      .build()

    (
      PublicKeyCredential
        .builder()
        .id(
          response.getAttestation.getAuthenticatorData.getAttestedCredentialData.get.getCredentialId
        )
        .response(response)
        .clientExtensionResults(clientExtensions)
        .build(),
      credentialKeypair,
      attestationMaker.certChain,
    )
  }

  def createBasicAttestedCredential(
      aaguid: ByteArray = Defaults.aaguid,
      attestationMaker: AttestationMaker,
      keyAlgorithm: COSEAlgorithmIdentifier = Defaults.keyAlgorithm,
  ): (
      data.PublicKeyCredential[
        data.AuthenticatorAttestationResponse,
        ClientRegistrationExtensionOutputs,
      ],
      KeyPair,
      List[(X509Certificate, PrivateKey)],
  ) = {
    val (authData, credentialKeypair) = createAuthenticatorData(
      aaguid = aaguid,
      keyAlgorithm = keyAlgorithm,
    )

    createCredential(
      authDataBytes = authData,
      credentialKeypair = credentialKeypair,
      attestationMaker = attestationMaker,
    )
  }

  def createSelfAttestedCredential(
      attestationMaker: SelfAttestation => AttestationMaker,
      keyAlgorithm: COSEAlgorithmIdentifier = Defaults.keyAlgorithm,
  ): (
      data.PublicKeyCredential[
        data.AuthenticatorAttestationResponse,
        ClientRegistrationExtensionOutputs,
      ],
      KeyPair,
      List[(X509Certificate, PrivateKey)],
  ) = {
    val (authData, keypair) = createAuthenticatorData(credentialKeypair =
      Some(generateKeypair(keyAlgorithm))
    )
    val signer = SelfAttestation(keypair, keyAlgorithm)
    createCredential(
      authDataBytes = authData,
      credentialKeypair = keypair,
      attestationMaker = attestationMaker(signer),
    )
  }

  def createUnattestedCredential(
      authenticatorExtensions: Option[JsonNode] = None,
      challenge: ByteArray = Defaults.challenge,
      flags: Option[AuthenticatorDataFlags] = None,
  ): (
      PublicKeyCredential[
        AuthenticatorAttestationResponse,
        ClientRegistrationExtensionOutputs,
      ],
      KeyPair,
      List[(X509Certificate, PrivateKey)],
  ) = {
    val (authData, keypair) = createAuthenticatorData(
      authenticatorExtensions = authenticatorExtensions,
      flags = flags,
    )
    createCredential(
      authDataBytes = authData,
      clientDataJson = Some(createClientData(challenge = challenge)),
      credentialKeypair = keypair,
      attestationMaker = AttestationMaker.none(),
    )
  }

  def createAssertionFromTestData(
      testData: RegistrationTestData,
      request: PublicKeyCredentialRequestOptions,
      authenticatorExtensions: Option[JsonNode] = None,
      origin: String = Defaults.origin,
      tokenBindingStatus: String = Defaults.TokenBinding.status,
      tokenBindingId: Option[String] = Defaults.TokenBinding.id,
      withUserHandle: Boolean = false,
  ): data.PublicKeyCredential[
    AuthenticatorAssertionResponse,
    ClientAssertionExtensionOutputs,
  ] = {
    createAssertion(
      alg = testData.alg,
      authenticatorExtensions = authenticatorExtensions,
      challenge = request.getChallenge,
      clientData = None,
      clientExtensions = ClientAssertionExtensionOutputs.builder().build(),
      credentialId = testData.response.getId,
      credentialKey = testData.keypair.get,
      origin = origin,
      tokenBindingStatus = tokenBindingStatus,
      tokenBindingId = tokenBindingId,
      userHandle = if (withUserHandle) Some(testData.userId.getId) else None,
    )
  }

  def createAssertion(
      alg: COSEAlgorithmIdentifier = COSEAlgorithmIdentifier.ES256,
      authenticatorExtensions: Option[JsonNode] = None,
      challenge: ByteArray = Defaults.challenge,
      clientData: Option[JsonNode] = None,
      clientExtensions: ClientAssertionExtensionOutputs =
        ClientAssertionExtensionOutputs.builder().build(),
      credentialId: ByteArray = Defaults.credentialId,
      credentialKey: KeyPair = Defaults.credentialKey,
      flags: Option[AuthenticatorDataFlags] = None,
      origin: String = Defaults.origin,
      signatureCount: Option[Int] = None,
      tokenBindingStatus: String = Defaults.TokenBinding.status,
      tokenBindingId: Option[String] = Defaults.TokenBinding.id,
      userHandle: Option[ByteArray] = None,
  ): data.PublicKeyCredential[
    data.AuthenticatorAssertionResponse,
    ClientAssertionExtensionOutputs,
  ] = {

    val clientDataJson: String =
      JacksonCodecs.json.writeValueAsString(clientData getOrElse {
        jsonMap {
          f =>
            Map(
              "challenge" -> f.textNode(challenge.getBase64Url),
              "origin" -> f.textNode(origin),
              "type" -> f.textNode("webauthn.get"),
              "tokenBinding" -> {
                val tokenBinding = f.objectNode()
                tokenBinding.set("status", f.textNode(tokenBindingStatus))
                tokenBindingId foreach { id =>
                  tokenBinding.set("id", f.textNode(id))
                }
                tokenBinding
              },
            )
        }
      })
    val clientDataJsonBytes = toBytes(clientDataJson)

    val authDataBytes: ByteArray =
      makeAuthDataBytes(
        flags = flags,
        signatureCount = signatureCount,
        rpId = Defaults.rpId,
        extensionsCborBytes = authenticatorExtensions map (ext =>
          new ByteArray(JacksonCodecs.cbor().writeValueAsBytes(ext))
        ),
      )

    val response = AuthenticatorAssertionResponse
      .builder()
      .authenticatorData(authDataBytes)
      .clientDataJSON(clientDataJsonBytes)
      .signature(
        makeAssertionSignature(
          authDataBytes,
          Crypto.sha256(clientDataJsonBytes),
          credentialKey.getPrivate,
          alg,
        )
      )
      .userHandle(userHandle.toJava)
      .build()

    PublicKeyCredential
      .builder()
      .id(credentialId)
      .response(response)
      .clientExtensionResults(clientExtensions)
      .build()
  }

  def makeU2fAttestationStatement(
      authDataBytes: ByteArray,
      clientDataJson: ByteArray,
      signer: AttestationSigner,
  ): JsonNode = {
    val authData = new AuthenticatorData(authDataBytes)

    def makeSignedData(
        rpIdHash: ByteArray,
        clientDataJson: ByteArray,
        credentialId: ByteArray,
        credentialPublicKeyRawBytes: ByteArray,
    ): ByteArray = {
      new ByteArray(
        (Vector[Byte](0)
          ++ rpIdHash.getBytes
          ++ Crypto.sha256(clientDataJson).getBytes
          ++ credentialId.getBytes
          ++ credentialPublicKeyRawBytes.getBytes).toArray
      )
    }

    val signedData = makeSignedData(
      authData.getRpIdHash,
      clientDataJson,
      authData.getAttestedCredentialData.get.getCredentialId,
      WebAuthnCodecs.ecPublicKeyToRaw(
        WebAuthnCodecs
          .importCosePublicKey(
            authData.getAttestedCredentialData.get.getCredentialPublicKey
          )
          .asInstanceOf[ECPublicKey]
      ),
    )

    jsonMap { f =>
      Map(
        "x5c" -> f.arrayNode().add(f.binaryNode(signer.cert.getEncoded)),
        "sig" -> f.binaryNode(
          sign(
            signedData,
            signer.key,
            signer.alg,
          ).getBytes
        ),
      )
    }
  }

  def makeNoneAttestationStatement(): JsonNode = jsonFactory.objectNode()

  def makePackedAttestationStatement(
      authDataBytes: ByteArray,
      clientDataJson: ByteArray,
      signer: AttestationSigner,
  ): JsonNode = {
    val signedData = new ByteArray(
      authDataBytes.getBytes ++ Crypto.sha256(clientDataJson).getBytes
    )
    val signature = signer match {
      case SelfAttestation(keypair, alg) =>
        sign(signedData, keypair.getPrivate, alg)
      case AttestationCert(_, key, alg, _) => sign(signedData, key, alg)
    }

    jsonMap { f =>
      Map(
        "alg" -> f.numberNode(signer.alg.getId),
        "sig" -> f.binaryNode(signature.getBytes),
      ) ++ (signer match {
        case _: SelfAttestation => Map.empty
        case AttestationCert(cert, _, _, _) =>
          Map(
            "x5c" -> f
              .arrayNode()
              .add(cert.getEncoded)
          )
      })
    }
  }

  def makeAndroidSafetynetAttestationStatement(
      authDataBytes: ByteArray,
      clientDataJson: ByteArray,
      cert: AttestationCert,
      ctsProfileMatch: Boolean = true,
  ): JsonNode = {
    val nonce =
      Crypto.sha256(authDataBytes concat Crypto.sha256(clientDataJson))

    val jwsHeader = jsonMap { f =>
      Map(
        "alg" -> f.textNode("RS256"),
        "x5c" -> f
          .arrayNode()
          .add(new ByteArray(cert.cert.getEncoded).getBase64),
      )
    }
    val jwsHeaderBase64 = new ByteArray(
      JacksonCodecs.json().writeValueAsBytes(jwsHeader)
    ).getBase64Url

    val jwsPayload = jsonMap { f =>
      Map(
        "nonce" -> f.textNode(nonce.getBase64),
        "timestampMs" -> f.numberNode(Instant.now().toEpochMilli),
        "apkPackageName" -> f.textNode("com.yubico.webauthn.test"),
        "apkDigestSha256" -> f.textNode(Crypto.sha256("foo").getBase64),
        "ctsProfileMatch" -> f.booleanNode(ctsProfileMatch),
        "aplCertificateDigestSha256" -> f
          .arrayNode()
          .add(f.textNode(Crypto.sha256("foo").getBase64)),
        "basicIntegrity" -> f.booleanNode(true),
      )
    }
    val jwsPayloadBase64 = new ByteArray(
      JacksonCodecs.json().writeValueAsBytes(jwsPayload)
    ).getBase64Url

    val jwsSignedCompact = jwsHeaderBase64 + "." + jwsPayloadBase64
    val jwsSignedBytes = new ByteArray(
      jwsSignedCompact.getBytes(StandardCharsets.UTF_8)
    )
    val jwsSignature = sign(jwsSignedBytes, cert.key, cert.alg)

    val jwsCompact = jwsSignedCompact + "." + jwsSignature.getBase64Url

    val attStmt = jsonMap { f =>
      Map(
        "ver" -> f.textNode("14799021"),
        "response" -> f.binaryNode(
          jwsCompact.getBytes(StandardCharsets.UTF_8)
        ),
      )
    }

    attStmt
  }

  def makeAppleAttestationStatement(
      caCert: X509Certificate,
      caKey: PrivateKey,
      authDataBytes: ByteArray,
      clientDataJson: ByteArray,
      addNonceExtension: Boolean = true,
      nonceValue: Option[ByteArray] = None,
      certSubjectPublicKey: Option[PublicKey] = None,
  ): JsonNode = {
    val clientDataJsonHash = Crypto.sha256(clientDataJson)
    val nonceToHash = authDataBytes.concat(clientDataJsonHash)
    val nonce = Crypto.sha256(nonceToHash)

    val subjectCert = buildCertificate(
      certSubjectPublicKey.getOrElse(
        WebAuthnTestCodecs.importCosePublicKey(
          new AuthenticatorData(
            authDataBytes
          ).getAttestedCredentialData.get.getCredentialPublicKey
        )
      ),
      new X500Name(
        "CN=Yubico WebAuthn unit tests CA, O=Yubico, OU=Apple Attestation"
      ),
      new X500Name(
        "CN=Apple attestation test credential, O=Yubico, OU=Apple Attestation"
      ),
      caKey,
      COSEAlgorithmIdentifier.ES256,
      extensions = if (addNonceExtension) {
        List(
          (
            "1.2.840.113635.100.8.2",
            false,
            new DERSequence(
              new DERTaggedObject(
                1,
                new DEROctetString(nonceValue.getOrElse(nonce).getBytes),
              )
            ),
          )
        )
      } else Nil,
    )

    jsonMap { f =>
      Map(
        "x5c" -> f
          .arrayNode()
          .addAll(
            List(subjectCert, caCert)
              .map(crt => f.binaryNode(crt.getEncoded))
              .asJava
          )
      )
    }
  }

  def makeTpmAttestationStatement(
      authDataBytes: ByteArray,
      clientDataJson: ByteArray,
      cert: AttestationCert,
      ver: Option[String] = Some("2.0"),
      magic: ByteArray = TpmAttestationStatementVerifier.TPM_GENERATED_VALUE,
      `type`: ByteArray = TpmAttestationStatementVerifier.TPM_ST_ATTEST_CERTIFY,
      modifyAttestedName: ByteArray => ByteArray = an => an,
      overrideCosePubkey: Option[ByteArray] = None,
      attributes: Option[Long] = None,
      symmetric: Option[Int] = None,
      scheme: Option[Int] = None,
  ): JsonNode = {
    assert(magic.size() == 4)
    assert(`type`.size() == 2)

    val authData = new AuthenticatorData(authDataBytes)
    val cosePubkey = overrideCosePubkey.getOrElse(
      authData.getAttestedCredentialData.get.getCredentialPublicKey
    )

    val coseKeyAlg = COSEAlgorithmIdentifier.fromPublicKey(cosePubkey).get
    val (hashId, signAlg) = coseKeyAlg match {
      case COSEAlgorithmIdentifier.ES256 =>
        (TpmAlgHash.SHA256, TpmAlgAsym.ECC)
      case COSEAlgorithmIdentifier.ES384 =>
        (TpmAlgHash.SHA384, TpmAlgAsym.ECC)
      case COSEAlgorithmIdentifier.ES512 =>
        (TpmAlgHash.SHA512, TpmAlgAsym.ECC)
      case COSEAlgorithmIdentifier.RS256 =>
        (TpmAlgHash.SHA256, TpmAlgAsym.RSA)
      case COSEAlgorithmIdentifier.RS384 =>
        (TpmAlgHash.SHA384, TpmAlgAsym.RSA)
      case COSEAlgorithmIdentifier.RS512 =>
        (TpmAlgHash.SHA512, TpmAlgAsym.RSA)
      case COSEAlgorithmIdentifier.RS1   => (TpmAlgHash.SHA1, TpmAlgAsym.RSA)
      case COSEAlgorithmIdentifier.EdDSA => ???
    }
    val hashFunc = hashId match {
      case TpmAlgHash.SHA256 => Crypto.sha256(_: ByteArray)
      case TpmAlgHash.SHA384 => Crypto.sha384 _
      case TpmAlgHash.SHA512 => Crypto.sha512 _
      case TpmAlgHash.SHA1   => Crypto.sha1 _
    }
    val extraData = hashFunc(
      authDataBytes concat Crypto.sha256(clientDataJson)
    )

    val (parameters, unique) = WebAuthnTestCodecs.getCoseKty(cosePubkey) match {
      case 3 => { // RSA
        val cose = CBORObject.DecodeFromBytes(cosePubkey.getBytes)
        (
          BinaryUtil.concat(
            BinaryUtil.encodeUint16(symmetric getOrElse 0x0010),
            BinaryUtil.encodeUint16(scheme getOrElse TpmRsaScheme.RSASSA),
            // key_bits
            BinaryUtil.encodeUint16(RsaKeySizeBits),
            // exponent
            BinaryUtil.encodeUint32(
              new BigInteger(1, cose.get(-2).GetByteString()).longValue()
            ),
          ),
          BinaryUtil.concat(
            BinaryUtil.encodeUint16(cose.get(-1).GetByteString().length),
            // modulus
            cose.get(-1).GetByteString(),
          ),
        )
      }
      case 2 => { // EC
        val pubkey = WebAuthnCodecs
          .importCosePublicKey(cosePubkey)
          .asInstanceOf[ECPublicKey]
        (
          BinaryUtil.concat(
            BinaryUtil.encodeUint16(symmetric getOrElse 0x0010),
            BinaryUtil.encodeUint16(scheme getOrElse 0x0010),
            BinaryUtil.encodeUint16(coseKeyAlg match {
              case COSEAlgorithmIdentifier.ES256 => 0x0003
              case COSEAlgorithmIdentifier.ES384 => 0x0004
              case COSEAlgorithmIdentifier.ES512 => 0x0005
              case COSEAlgorithmIdentifier.RS1 | COSEAlgorithmIdentifier.RS256 |
                  COSEAlgorithmIdentifier.RS384 |
                  COSEAlgorithmIdentifier.RS512 |
                  COSEAlgorithmIdentifier.EdDSA =>
                ???
            }),
            // kdf_scheme: ??? (unused?)
            BinaryUtil.encodeUint16(0x0010),
          ),
          BinaryUtil.concat(
            BinaryUtil.encodeUint16(pubkey.getW.getAffineX.toByteArray.length),
            pubkey.getW.getAffineX.toByteArray,
            BinaryUtil.encodeUint16(
              pubkey.getW.getAffineY.toByteArray.length
            ),
            pubkey.getW.getAffineY.toByteArray,
          ),
        )
      }
    }
    val pubArea = new ByteArray(
      BinaryUtil.concat(
        BinaryUtil.encodeUint16(signAlg),
        BinaryUtil.encodeUint16(hashId),
        BinaryUtil.encodeUint32(attributes getOrElse Attributes.SIGN_ENCRYPT),
        // authPolicy is ignored by TpmAttestationStatementVerifier
        BinaryUtil.encodeUint16(0),
        parameters,
        unique,
      )
    )

    val qualifiedSigner = BinaryUtil.fromHex("")
    val clockInfo = BinaryUtil.fromHex("0000000000000000111111112222222233")
    val firmwareVersion = BinaryUtil.fromHex("0000000000000000")
    val attestedName =
      modifyAttestedName(
        new ByteArray(BinaryUtil.encodeUint16(hashId)).concat(hashFunc(pubArea))
      )
    val attestedQualifiedName = BinaryUtil.fromHex("")

    val certInfo = new ByteArray(
      BinaryUtil.concat(
        magic.getBytes,
        `type`.getBytes,
        BinaryUtil.encodeUint16(qualifiedSigner.length),
        qualifiedSigner,
        BinaryUtil.encodeUint16(extraData.size),
        extraData.getBytes,
        clockInfo,
        firmwareVersion,
        BinaryUtil.encodeUint16(attestedName.size),
        attestedName.getBytes,
        BinaryUtil.encodeUint16(attestedQualifiedName.length),
        attestedQualifiedName,
      )
    )

    val sig = sign(certInfo, cert.key, cert.alg)

    jsonMap { f =>
      Map(
        "ver" -> ver.map(f.textNode).getOrElse(f.nullNode()),
        "alg" -> f.numberNode(cert.alg.getId),
        "x5c" -> f
          .arrayNode()
          .addAll(
            cert.certChain.map(_._1.getEncoded).map(f.binaryNode).asJava
          ),
        "sig" -> f.binaryNode(sig.getBytes),
        "certInfo" -> f.binaryNode(certInfo.getBytes),
        "pubArea" -> f.binaryNode(pubArea.getBytes),
      )
    }
  }

  def makeAuthDataBytes(
      rpId: String = Defaults.rpId,
      flags: Option[AuthenticatorDataFlags] = None,
      signatureCount: Option[Int] = None,
      attestedCredentialDataBytes: Option[ByteArray] = None,
      extensionsCborBytes: Option[ByteArray] = None,
  ): ByteArray = {
    val atFlag = if (attestedCredentialDataBytes.isDefined) 0x40 else 0x00
    val edFlag = if (extensionsCborBytes.isDefined) 0x80 else 0x00
    new ByteArray(
      (Vector[Byte]()
        ++ sha256(rpId).getBytes.toVector
        ++ Some[Byte](
          (flags
            .map(_.value)
            .getOrElse(0x00.toByte) | 0x01 | atFlag | edFlag).toByte
        )
        ++ BinaryUtil
          .encodeUint32(signatureCount.getOrElse(1337).toLong)
          .toVector
        ++ (attestedCredentialDataBytes map {
          _.getBytes.toVector
        } getOrElse Nil)
        ++ (extensionsCborBytes map {
          _.getBytes.toVector
        } getOrElse Nil)).toArray
    )
  }

  def makeAttestedCredentialDataBytes(
      publicKeyCose: ByteArray,
      aaguid: ByteArray = Defaults.aaguid,
  ): ByteArray = {
    val credentialId = sha256(publicKeyCose)

    new ByteArray(
      (Vector[Byte]()
        ++ aaguid.getBytes.toVector
        ++ BinaryUtil.fromHex("0020").toVector
        ++ credentialId.getBytes.toVector
        ++ publicKeyCose.getBytes.toVector).toArray
    )
  }

  def makeAssertionSignature(
      authenticatorData: ByteArray,
      clientDataHash: ByteArray,
      key: PrivateKey,
      alg: COSEAlgorithmIdentifier = COSEAlgorithmIdentifier.ES256,
  ): ByteArray =
    sign(authenticatorData.concat(clientDataHash), key, alg)

  def sign(
      data: ByteArray,
      key: PrivateKey,
      alg: COSEAlgorithmIdentifier,
  ): ByteArray = {
    val jAlg = WebAuthnCodecs.getJavaAlgorithmName(alg)

    // Need to use BouncyCastle provider here because JDK15 standard providers do not support secp256k1
    val sig = Signature.getInstance(jAlg, new BouncyCastleProvider())

    sig.initSign(key)
    sig.update(data.getBytes)
    new ByteArray(sig.sign())
  }

  def generateKeypair(algorithm: COSEAlgorithmIdentifier): KeyPair =
    algorithm match {
      case COSEAlgorithmIdentifier.EdDSA => generateEddsaKeypair()
      case COSEAlgorithmIdentifier.ES256 => generateEcKeypair("secp256r1")
      case COSEAlgorithmIdentifier.ES384 => generateEcKeypair("secp384r1")
      case COSEAlgorithmIdentifier.ES512 => generateEcKeypair("secp521r1")
      case COSEAlgorithmIdentifier.RS256 | COSEAlgorithmIdentifier.RS384 |
          COSEAlgorithmIdentifier.RS512 | COSEAlgorithmIdentifier.RS1 =>
        generateRsaKeypair()
    }

  def generateEcKeypair(curve: String = "secp256r1"): KeyPair = {
    val ecSpec = new ECGenParameterSpec(curve)

    // Need to use BouncyCastle provider here because JDK15 standard providers do not support secp256k1
    val g: KeyPairGenerator =
      KeyPairGenerator.getInstance("EC", new BouncyCastleProvider())

    g.initialize(ecSpec, random)

    g.generateKeyPair()
  }

  def generateEddsaKeypair(): KeyPair = {
    val alg = "Ed25519"
    // Need to use BouncyCastle provider here because JDK before 14 does not support EdDSA
    val keyPairGenerator =
      KeyPairGenerator.getInstance(alg, new BouncyCastleProvider())
    keyPairGenerator.generateKeyPair()
  }

  def importEcKeypair(
      privateBytes: ByteArray,
      publicBytes: ByteArray,
  ): KeyPair = {
    val keyFactory: KeyFactory = KeyFactory.getInstance("EC")

    new KeyPair(
      keyFactory.generatePublic(new X509EncodedKeySpec(publicBytes.getBytes)),
      keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateBytes.getBytes)),
    )
  }

  def generateRsaKeypair(): KeyPair = {
    val g: KeyPairGenerator = KeyPairGenerator.getInstance("RSA")
    g.initialize(RsaKeySizeBits, random)
    g.generateKeyPair()
  }

  def verifyEcSignature(
      pubKey: PublicKey,
      signedDataBytes: ByteArray,
      signatureBytes: ByteArray,
  ): Boolean = {
    val alg = "SHA256withECDSA"
    val sig: Signature = Signature.getInstance(alg)
    sig.initVerify(pubKey)
    sig.update(signedDataBytes.getBytes)

    sig.verify(signatureBytes.getBytes) &&
    Crypto.verifySignature(
      pubKey,
      signedDataBytes,
      signatureBytes,
      COSEAlgorithmIdentifier.ES256,
    )
  }

  def verifyU2fExampleWithCert(
      attestationCertBytes: ByteArray,
      signedDataBytes: ByteArray,
      signatureBytes: ByteArray,
  ): Unit = {
    val attestationCert: X509Certificate =
      CertificateParser.parseDer(attestationCertBytes.getBytes)
    val pubKey: PublicKey = attestationCert.getPublicKey
    verifyEcSignature(pubKey, signedDataBytes, signatureBytes)
  }

  def verifyU2fExampleWithExplicitParams(
      publicKeyHex: String,
      signedDataBytes: ByteArray,
      signatureBytes: ByteArray,
  ): Unit = {
    val pubKeyPoint = new ECPoint(
      new BigInteger(publicKeyHex drop 2 take 64, 16),
      new BigInteger(publicKeyHex drop 2 drop 64, 16),
    )
    val namedSpec = ECNamedCurveTable.getParameterSpec("P-256")
    val curveSpec: ECNamedCurveSpec = new ECNamedCurveSpec(
      "P-256",
      namedSpec.getCurve,
      namedSpec.getG,
      namedSpec.getN,
    )
    val pubKeySpec: ECPublicKeySpec =
      new ECPublicKeySpec(pubKeyPoint, curveSpec)
    val keyFactory: KeyFactory = KeyFactory.getInstance("EC")
    val pubKey: PublicKey = keyFactory.generatePublic(pubKeySpec)
    verifyEcSignature(pubKey, signedDataBytes, signatureBytes)
  }

  def generateAttestationCaCertificate(
      keypair: Option[KeyPair] = None,
      signingAlg: COSEAlgorithmIdentifier = COSEAlgorithmIdentifier.ES256,
      name: X500Name = Defaults.caCertSubject,
      superCa: Option[(X509Certificate, PrivateKey)] = None,
      extensions: Iterable[(String, Boolean, ASN1Primitive)] = Nil,
      validFrom: Instant = Defaults.certValidFrom,
      validTo: Instant = Defaults.certValidTo,
  ): (X509Certificate, PrivateKey) = {
    val actualKeypair = keypair.getOrElse(generateKeypair(signingAlg))
    (
      buildCertificate(
        publicKey = actualKeypair.getPublic,
        issuerName =
          superCa map (_._1) map JcaX500NameUtil.getSubject getOrElse name,
        subjectName = name,
        signingKey = superCa map (_._2) getOrElse actualKeypair.getPrivate,
        signingAlg = signingAlg,
        isCa = true,
        extensions = extensions,
        validFrom = validFrom,
        validTo = validTo,
      ),
      actualKeypair.getPrivate,
    )
  }

  def generateAttestationCertificate(
      alg: COSEAlgorithmIdentifier = COSEAlgorithmIdentifier.ES256,
      keypair: Option[KeyPair] = None,
      name: X500Name = Defaults.leafCertSubject,
      issuerName: Option[X500Name] = None,
      extensions: Iterable[(String, Boolean, ASN1Encodable)] = List(
        (
          "1.3.6.1.4.1.45724.1.1.4",
          false,
          new DEROctetString(Defaults.aaguid.getBytes),
        )
      ),
      caCertAndKey: Option[(X509Certificate, PrivateKey)] = None,
      validFrom: Instant = Defaults.certValidFrom,
      validTo: Instant = Defaults.certValidTo,
      isCa: Boolean = false,
  ): (X509Certificate, PrivateKey) = {
    val actualKeypair = keypair.getOrElse(generateKeypair(alg))

    (
      buildCertificate(
        publicKey = actualKeypair.getPublic,
        issuerName = issuerName.getOrElse(
          caCertAndKey
            .map(_._1)
            .map(JcaX500NameUtil.getSubject)
            .getOrElse(name)
        ),
        subjectName = name,
        signingKey = caCertAndKey.map(_._2).getOrElse(actualKeypair.getPrivate),
        signingAlg = alg,
        isCa = isCa,
        extensions = extensions,
        validFrom = validFrom,
        validTo = validTo,
      ),
      actualKeypair.getPrivate,
    )
  }

  def buildCertificate(
      publicKey: PublicKey,
      issuerName: X500Name,
      subjectName: X500Name,
      signingKey: PrivateKey,
      signingAlg: COSEAlgorithmIdentifier,
      isCa: Boolean = false,
      extensions: Iterable[(String, Boolean, ASN1Encodable)] = None,
      validFrom: Instant = Defaults.certValidFrom,
      validTo: Instant = Defaults.certValidTo,
  ): X509Certificate = {
    CertificateParser.parseDer({
      val builder = new X509v3CertificateBuilder(
        issuerName,
        BigInteger.valueOf(random.nextInt(10000)),
        Date.from(validFrom),
        Date.from(validTo),
        subjectName,
        SubjectPublicKeyInfo.getInstance(publicKey.getEncoded),
      )

      for { (oid, critical, value) <- extensions } {
        builder.addExtension(new ASN1ObjectIdentifier(oid), critical, value)
      }

      if (isCa) {
        builder.addExtension(
          Extension.basicConstraints,
          true,
          new BasicConstraints(true),
        );
      }

      val signerBuilder = new JcaContentSignerBuilder(
        WebAuthnCodecs.getJavaAlgorithmName(signingAlg)
      )
        .setProvider(
          new BouncyCastleProvider()
        ) // Needed because JDK15 standard providers do not support secp256k1

      builder.build(signerBuilder.build(signingKey)).getEncoded
    })
  }

  def buildCrl(
      issuerName: X500Name,
      signingKey: PrivateKey,
      signingAlgJavaName: String,
      currentTime: Instant,
      nextUpdate: Instant,
      revoked: Set[X509Certificate] = Set.empty,
  ): CRL = {
    java.security.cert.CertificateFactory
      .getInstance("X.509")
      .generateCRL(new ByteArrayInputStream({
        val builder = new X509v2CRLBuilder(issuerName, Date.from(currentTime))
        builder.setNextUpdate(Date.from(nextUpdate))

        for { revoked <- revoked } {
          builder.addCRLEntry(
            revoked.getSerialNumber,
            Date.from(currentTime),
            ReasonFlags.cessationOfOperation,
          )
        }

        val signerBuilder = new JcaContentSignerBuilder(signingAlgJavaName)
        builder.build(signerBuilder.build(signingKey)).getEncoded
      }))
  }

  def generateRsaCertificate(): (X509Certificate, PrivateKey) =
    generateAttestationCertificate(COSEAlgorithmIdentifier.RS256)

  def coseAlgorithmOfJavaKey(key: PrivateKey): COSEAlgorithmIdentifier =
    Try(COSEAlgorithmIdentifier.valueOf(key.getAlgorithm)) getOrElse
      key match {
      case key: BCECPrivateKey =>
        key.getParameters.getCurve match {
          case _: SecP256R1Curve => COSEAlgorithmIdentifier.valueOf("ES256")
        }
    }

}
