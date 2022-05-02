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
import com.yubico.internal.util.BinaryUtil
import com.yubico.internal.util.CertificateParser
import com.yubico.internal.util.JacksonCodecs
import com.yubico.webauthn.data.AuthenticatorAssertionResponse
import com.yubico.webauthn.data.AuthenticatorAttestationResponse
import com.yubico.webauthn.data.AuthenticatorData
import com.yubico.webauthn.data.ByteArray
import com.yubico.webauthn.data.COSEAlgorithmIdentifier
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs
import com.yubico.webauthn.data.ClientRegistrationExtensionOutputs
import com.yubico.webauthn.data.PublicKeyCredential
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions
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

    val certValidFrom: Instant = Instant.parse("2018-09-06T17:42:00Z")
    val certValidTo: Instant = certValidFrom.plusSeconds(7 * 24 * 3600)
  }

  private def jsonFactory: JsonNodeFactory = JsonNodeFactory.instance
  private def toBytes(s: String): ByteArray = new ByteArray(s.getBytes("UTF-8"))
  def sha256(s: String): ByteArray = sha256(toBytes(s))
  def sha256(b: ByteArray): ByteArray =
    new ByteArray(MessageDigest.getInstance("SHA-256").digest(b.getBytes))

  sealed trait AttestationMaker {
    val format: String
    def makeAttestationStatement(
        authDataBytes: ByteArray,
        clientDataJson: String,
    ): JsonNode
    def certChain: List[(X509Certificate, PrivateKey)] = Nil

    def makeAttestationObjectBytes(
        authDataBytes: ByteArray,
        clientDataJson: String,
    ): ByteArray = {
      val f = JsonNodeFactory.instance
      val attObj = f
        .objectNode()
        .setAll[ObjectNode](
          Map(
            "authData" -> f.binaryNode(authDataBytes.getBytes),
            "fmt" -> f.textNode(format),
            "attStmt" -> makeAttestationStatement(authDataBytes, clientDataJson),
          ).asJava
        )
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
            clientDataJson: String,
        ): JsonNode =
          makePackedAttestationStatement(authDataBytes, clientDataJson, signer)
      }
    def fidoU2f(signer: AttestationSigner): AttestationMaker =
      new AttestationMaker {
        override val format = "fido-u2f"
        override def certChain = signer.certChain
        override def makeAttestationStatement(
            authDataBytes: ByteArray,
            clientDataJson: String,
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
            clientDataJson: String,
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
              clientDataJson: String,
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

    def none(): AttestationMaker =
      new AttestationMaker {
        override val format = "none"
        override def certChain = Nil
        override def makeAttestationStatement(
            authDataBytes: ByteArray,
            clientDataJson: String,
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
        aaguid: ByteArray = Defaults.aaguid,
        certSubject: X500Name = new X500Name(
          "CN=Yubico WebAuthn unit tests, O=Yubico, OU=Authenticator Attestation, C=SE"
        ),
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
        extensions = List(
          (
            "1.3.6.1.4.1.45724.1.1.4",
            false,
            new DEROctetString(aaguid.getBytes),
          )
        ),
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

    def selfsigned(alg: COSEAlgorithmIdentifier): AttestationCert = {
      val (cert, key) = generateAttestationCertificate(alg = alg)
      AttestationCert(cert, key, alg, certChain = List((cert, key)))
    }
  }

  private def createCredential(
      aaguid: ByteArray = Defaults.aaguid,
      attestationMaker: AttestationMaker,
      authenticatorExtensions: Option[JsonNode] = None,
      challenge: ByteArray = Defaults.challenge,
      clientData: Option[JsonNode] = None,
      clientExtensions: ClientRegistrationExtensionOutputs =
        ClientRegistrationExtensionOutputs.builder().build(),
      credentialKeypair: Option[KeyPair] = None,
      keyAlgorithm: COSEAlgorithmIdentifier = Defaults.keyAlgorithm,
      origin: String = Defaults.origin,
      tokenBindingStatus: String = Defaults.TokenBinding.status,
      tokenBindingId: Option[String] = Defaults.TokenBinding.id,
  ): (
      data.PublicKeyCredential[
        data.AuthenticatorAttestationResponse,
        ClientRegistrationExtensionOutputs,
      ],
      KeyPair,
      List[(X509Certificate, PrivateKey)],
  ) = {

    val clientDataJson: String =
      JacksonCodecs.json.writeValueAsString(clientData getOrElse {
        val json: ObjectNode = jsonFactory.objectNode()

        json.setAll(
          Map(
            "challenge" -> jsonFactory.textNode(challenge.getBase64Url),
            "origin" -> jsonFactory.textNode(origin),
            "type" -> jsonFactory.textNode("webauthn.create"),
          ).asJava
        )

        json.set(
          "tokenBinding", {
            val tokenBinding = jsonFactory.objectNode()
            tokenBinding.set("status", jsonFactory.textNode(tokenBindingStatus))
            tokenBindingId foreach { id =>
              tokenBinding.set("id", jsonFactory.textNode(id))
            }
            tokenBinding
          },
        )

        json
      })
    val clientDataJsonBytes = toBytes(clientDataJson)

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

    val attestationObjectBytes =
      attestationMaker.makeAttestationObjectBytes(authDataBytes, clientDataJson)

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
      keypair,
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
  ) =
    createCredential(
      aaguid = aaguid,
      attestationMaker = attestationMaker,
      keyAlgorithm = keyAlgorithm,
    )

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
    val keypair = generateKeypair(keyAlgorithm)
    val signer = SelfAttestation(keypair, keyAlgorithm)
    createCredential(
      attestationMaker = attestationMaker(signer),
      credentialKeypair = Some(keypair),
      keyAlgorithm = keyAlgorithm,
    )
  }

  def createUnattestedCredential(
      authenticatorExtensions: Option[JsonNode] = None,
      challenge: ByteArray = Defaults.challenge,
  ): (
      PublicKeyCredential[
        AuthenticatorAttestationResponse,
        ClientRegistrationExtensionOutputs,
      ],
      KeyPair,
      List[(X509Certificate, PrivateKey)],
  ) =
    createCredential(
      attestationMaker = AttestationMaker.none(),
      authenticatorExtensions = authenticatorExtensions,
      challenge = challenge,
    )

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
        val json: ObjectNode = jsonFactory.objectNode()

        json.setAll(
          Map(
            "challenge" -> jsonFactory.textNode(challenge.getBase64Url),
            "origin" -> jsonFactory.textNode(origin),
            "type" -> jsonFactory.textNode("webauthn.get"),
          ).asJava
        )

        json.set(
          "tokenBinding", {
            val tokenBinding = jsonFactory.objectNode()
            tokenBinding.set("status", jsonFactory.textNode(tokenBindingStatus))
            tokenBindingId foreach { id =>
              tokenBinding.set("id", jsonFactory.textNode(id))
            }
            tokenBinding
          },
        )

        json
      })
    val clientDataJsonBytes = toBytes(clientDataJson)

    val authDataBytes: ByteArray =
      makeAuthDataBytes(
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
      clientDataJson: String,
      signer: AttestationSigner,
  ): JsonNode = {
    val authData = new AuthenticatorData(authDataBytes)

    def makeSignedData(
        rpIdHash: ByteArray,
        clientDataJson: String,
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

    val f = JsonNodeFactory.instance
    f.objectNode()
      .setAll(
        Map(
          "x5c" -> f.arrayNode().add(f.binaryNode(signer.cert.getEncoded)),
          "sig" -> f.binaryNode(
            sign(
              signedData,
              signer.key,
              signer.alg,
            ).getBytes
          ),
        ).asJava
      )
  }

  def makeNoneAttestationStatement(): JsonNode =
    JsonNodeFactory.instance.objectNode()

  def makePackedAttestationStatement(
      authDataBytes: ByteArray,
      clientDataJson: String,
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

    val f = JsonNodeFactory.instance
    f.objectNode()
      .setAll(
        (
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
        ).asJava
      )
  }

  def makeAndroidSafetynetAttestationStatement(
      authDataBytes: ByteArray,
      clientDataJson: String,
      cert: AttestationCert,
      ctsProfileMatch: Boolean = true,
  ): JsonNode = {
    val nonce =
      Crypto.sha256(authDataBytes concat Crypto.sha256(clientDataJson))

    val f = JsonNodeFactory.instance

    val jwsHeader = f
      .objectNode()
      .setAll[ObjectNode](
        Map(
          "alg" -> f.textNode("RS256"),
          "x5c" -> f
            .arrayNode()
            .add(new ByteArray(cert.cert.getEncoded).getBase64),
        ).asJava
      )
    val jwsHeaderBase64 = new ByteArray(
      JacksonCodecs.json().writeValueAsBytes(jwsHeader)
    ).getBase64Url

    val jwsPayload = f
      .objectNode()
      .setAll[ObjectNode](
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
        ).asJava
      )
    val jwsPayloadBase64 = new ByteArray(
      JacksonCodecs.json().writeValueAsBytes(jwsPayload)
    ).getBase64Url

    val jwsSignedCompact = jwsHeaderBase64 + "." + jwsPayloadBase64
    val jwsSignedBytes = new ByteArray(
      jwsSignedCompact.getBytes(StandardCharsets.UTF_8)
    )
    val jwsSignature = sign(jwsSignedBytes, cert.key, cert.alg)

    val jwsCompact = jwsSignedCompact + "." + jwsSignature.getBase64Url

    val attStmt = f
      .objectNode()
      .setAll[ObjectNode](
        Map(
          "ver" -> f.textNode("14799021"),
          "response" -> f.binaryNode(
            jwsCompact.getBytes(StandardCharsets.UTF_8)
          ),
        ).asJava
      )

    attStmt
  }

  def makeAppleAttestationStatement(
      caCert: X509Certificate,
      caKey: PrivateKey,
      authDataBytes: ByteArray,
      clientDataJson: String,
      addNonceExtension: Boolean = true,
      nonceValue: Option[ByteArray] = None,
      certSubjectPublicKey: Option[PublicKey] = None,
  ): JsonNode = {
    val clientDataJSON = new ByteArray(
      clientDataJson.getBytes(StandardCharsets.UTF_8)
    )
    val clientDataJsonHash = Crypto.sha256(clientDataJSON)
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

    val f = JsonNodeFactory.instance
    f.objectNode()
      .setAll(
        Map(
          "x5c" -> f
            .arrayNode()
            .addAll(
              List(subjectCert, caCert)
                .map(crt => f.binaryNode(crt.getEncoded))
                .asJava
            )
        ).asJava
      )
  }

  def makeAuthDataBytes(
      rpId: String = Defaults.rpId,
      signatureCount: Option[Int] = None,
      attestedCredentialDataBytes: Option[ByteArray] = None,
      extensionsCborBytes: Option[ByteArray] = None,
  ): ByteArray =
    new ByteArray(
      (Vector[Byte]()
        ++ sha256(rpId).getBytes.toVector
        ++ Some[Byte](
          (0x01 | (if (attestedCredentialDataBytes.isDefined) 0x40
                   else 0x00) | (if (extensionsCborBytes.isDefined) 0x80
                                 else 0x00)).toByte
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
      case COSEAlgorithmIdentifier.ES256 => generateEcKeypair()
      case COSEAlgorithmIdentifier.RS256 => generateRsaKeypair()
      case COSEAlgorithmIdentifier.RS1   => generateRsaKeypair()
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
    g.initialize(2048, random)
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
      name: X500Name = new X500Name(
        "CN=Yubico WebAuthn unit tests CA, O=Yubico, OU=Authenticator Attestation, C=SE"
      ),
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
      name: X500Name = new X500Name(
        "CN=Yubico WebAuthn unit tests, O=Yubico, OU=Authenticator Attestation, C=SE"
      ),
      extensions: Iterable[(String, Boolean, ASN1Primitive)] = List(
        (
          "1.3.6.1.4.1.45724.1.1.4",
          false,
          new DEROctetString(Defaults.aaguid.getBytes),
        )
      ),
      caCertAndKey: Option[(X509Certificate, PrivateKey)] = None,
      validFrom: Instant = Defaults.certValidFrom,
      validTo: Instant = Defaults.certValidTo,
  ): (X509Certificate, PrivateKey) = {
    val actualKeypair = keypair.getOrElse(generateKeypair(alg))

    (
      buildCertificate(
        publicKey = actualKeypair.getPublic,
        issuerName = caCertAndKey
          .map(_._1)
          .map(JcaX500NameUtil.getSubject)
          .getOrElse(name),
        subjectName = name,
        signingKey = caCertAndKey.map(_._2).getOrElse(actualKeypair.getPrivate),
        signingAlg = alg,
        isCa = false,
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
      extensions: Iterable[(String, Boolean, ASN1Primitive)] = None,
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
