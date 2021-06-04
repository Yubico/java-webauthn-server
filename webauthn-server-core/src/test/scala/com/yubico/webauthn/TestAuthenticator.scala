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
import com.yubico.internal.util.scala.JavaConverters._
import com.yubico.webauthn.data.AuthenticatorAssertionResponse
import com.yubico.webauthn.data.AuthenticatorAttestationResponse
import com.yubico.webauthn.data.AuthenticatorData
import com.yubico.webauthn.data.ByteArray
import com.yubico.webauthn.data.COSEAlgorithmIdentifier
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs
import com.yubico.webauthn.data.ClientRegistrationExtensionOutputs
import com.yubico.webauthn.data.PublicKeyCredential
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions
import com.yubico.webauthn.test.Util
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.DERSequence
import org.bouncycastle.asn1.DERTaggedObject
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX500NameUtil
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECNamedCurveSpec
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder

import java.io.BufferedReader
import java.io.InputStream
import java.io.InputStreamReader
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
import scala.util.Try

object TestAuthenticator {

  def main(args: Array[String]): Unit = {
    val attestationCertBytes: ByteArray =
      ByteArray.fromHex("308201313081d8a003020102020441c4567d300a06082a8648ce3d0403023021311f301d0603550403131646697265666f782055324620536f667420546f6b656e301e170d3137303930353134303030345a170d3137303930373134303030345a3021311f301d0603550403131646697265666f782055324620536f667420546f6b656e3059301306072a8648ce3d020106082a8648ce3d03010703420004f9b7dfc17c8a7dcaacdaaad402c7f1f8570e3e9165f6ce2b9b9a4f64333405e1b952c516560bbe7d304d2da3b6582734dadd980e379b0f86a3e42cc657cffe84300a06082a8648ce3d0403020348003045022067fd4da98db1ddbcef53041d3cfd15ed6b8315cb4116889c2eabe6b50b7f985f02210098842f6835ee18181acc765f642fa124556121f418e108c5ec1bb22e9c28b76b")
    val publicKeyHex: String =
      "04f9b7dfc17c8a7dcaacdaaad402c7f1f8570e3e9165f6ce2b9b9a4f64333405e1b952c516560bbe7d304d2da3b6582734dadd980e379b0f86a3e42cc657cffe84"
    val signedDataBytes: ByteArray =
      ByteArray.fromHex("0049960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d976354543ac68315afe4cd7947adf5f7e8e7dc87ddf4582ef6e7fb467e5cad098af50008f926c96b3248cb3733c70a10e3e0995af0892220d6293780335390594e35a73a3743ed97c8e4fd9c0e183d60ccb764edac2fcbdb84b6b940089be98744673db427ce9d4f09261d4f6535bf52dcd216d9ba81a88f2ed5d7fa04bb25e641a3cd7ef9922fdb8d7d4b9f81a55f661b74f26d97a9382dda9a6b62c378cf6603b9f1218a87c158d88bf1ac51b0e4343657de0e9a6b6d60289fed2b46239abe00947e6a04c6733148283cb5786a678afc959262a71be0925da9992354ba6438022d68ae573285e5564196d62edfc46432cba9393c6138882856a0296b41f5b4b97e00e935")
    val signatureBytes: ByteArray =
      ByteArray.fromHex("3046022100a78ca2cb9feb402acc9f50d16d96487821122bbbdf70c8745a6d37161a16de09022100e10db1bf39b73b18acf9236f758558a7811e04a7901d12f7f34f503b171fe51e")

    verifyU2fExampleWithCert(
      attestationCertBytes,
      signedDataBytes,
      signatureBytes,
    )
    verifyU2fExampleWithExplicitParams(
      publicKeyHex,
      signedDataBytes,
      signatureBytes,
    )

    println(generateAttestationCertificate())

    val (credential, _) = createBasicAttestedCredential(attestationMaker =
      AttestationMaker.packed(
        AttestationSigner.selfsigned(COSEAlgorithmIdentifier.ES256)
      )
    )

    println(credential)
    println(
      s"Client data: ${new String(credential.getResponse.getClientDataJSON.getBytes, "UTF-8")}"
    )
    println(s"Client data: ${credential.getResponse.getClientDataJSON.getHex}")
    println(s"Client data: ${credential.getResponse.getClientData}")
    println(s"Attestation object: ${credential.getResponse.getAttestationObject.getHex}")
    println(s"Attestation object: ${credential.getResponse.getAttestation}")

    println("Javascript:")
    println(s"""parseCreateCredentialResponse({ response: { attestationObject: new Buffer("${credential.getResponse.getAttestationObject.getHex}", 'hex'), clientDataJSON: new Buffer("${credential.getResponse.getClientDataJSON.getHex}", 'hex') } })""")

    println(s"Public key: ${BinaryUtil.toHex(Defaults.credentialKey.getPublic.getEncoded)}")
    println(s"Private key: ${BinaryUtil.toHex(Defaults.credentialKey.getPrivate.getEncoded)}")

    val assertion = createAssertion()
    println(
      s"Assertion signature: ${assertion.getResponse.getSignature.getHex}"
    )
    println(s"Authenticator data: ${assertion.getResponse.getAuthenticatorData.getHex}")
    println(s"Client data: ${assertion.getResponse.getClientDataJSON.getHex}")
    println(
      s"Client data: ${new String(assertion.getResponse.getClientDataJSON.getBytes, "UTF-8")}"
    )
  }

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
  }

  private def jsonFactory: JsonNodeFactory = JsonNodeFactory.instance
  private def toBytes(s: String): ByteArray = new ByteArray(s.getBytes("UTF-8"))
  private def sha256(s: String): ByteArray = sha256(toBytes(s))
  private def sha256(b: ByteArray): ByteArray =
    new ByteArray(MessageDigest.getInstance("SHA-256").digest(b.getBytes))

  sealed trait AttestationMaker {
    val format: String
    def makeAttestationStatement(
        authDataBytes: ByteArray,
        clientDataJson: String,
    ): JsonNode
    def attestationCert: Option[X509Certificate] = ???

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
        override def attestationCert: Option[X509Certificate] =
          Some(signer.cert)
        override def makeAttestationStatement(
            authDataBytes: ByteArray,
            clientDataJson: String,
        ): JsonNode =
          makePackedAttestationStatement(authDataBytes, clientDataJson, signer)
      }
    def fidoU2f(signer: AttestationSigner): AttestationMaker =
      new AttestationMaker {
        override val format = "fido-u2f"
        override def attestationCert: Option[X509Certificate] =
          Some(signer.cert)
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
        override def attestationCert: Option[X509Certificate] = Some(cert.cert)
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
        override def attestationCert: Option[X509Certificate] = None
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
  }
  case class SelfAttestation(keypair: KeyPair, alg: COSEAlgorithmIdentifier)
      extends AttestationSigner {
    def key: PrivateKey = keypair.getPrivate
    def cert: X509Certificate =
      generateAttestationCertificate(alg = alg, keypair = Some(keypair))._1
  }
  case class AttestationCert(
      cert: X509Certificate,
      key: PrivateKey,
      alg: COSEAlgorithmIdentifier,
      chain: List[X509Certificate],
  ) extends AttestationSigner {
    def this(
        alg: COSEAlgorithmIdentifier,
        keypair: (X509Certificate, PrivateKey),
    ) = this(keypair._1, keypair._2, alg, Nil)
  }
  object AttestationSigner {
    def ca(
        alg: COSEAlgorithmIdentifier,
        certSubject: X500Name = new X500Name(
          "CN=Yubico WebAuthn unit tests CA, O=Yubico, OU=Authenticator Attestation, C=SE"
        ),
    ): AttestationCert = {
      val (caCert, caKey) =
        generateAttestationCaCertificate(signingAlg = alg, name = certSubject)
      val (cert, key) = generateAttestationCertificate(
        alg,
        caCertAndKey = Some((caCert, caKey)),
        name = certSubject,
      )
      AttestationCert(cert, key, alg, List(caCert))
    }

    def selfsigned(alg: COSEAlgorithmIdentifier): AttestationCert = {
      val (cert, key) = generateAttestationCertificate(alg = alg)
      AttestationCert(cert, key, alg, Nil)
    }
  }

  def makeCreateCredentialExample(
      publicKeyCredential: PublicKeyCredential[
        AuthenticatorAttestationResponse,
        ClientRegistrationExtensionOutputs,
      ]
  ): String =
    s"""Attestation object: ${publicKeyCredential.getResponse.getAttestationObject.getHex}
      |Client data: ${publicKeyCredential.getResponse.getClientDataJSON.getHex}
    """.stripMargin

  def makeAssertionExample(alg: COSEAlgorithmIdentifier): String = {
    val (_, keypair) =
      createCredential(attestationMaker = AttestationMaker.default())
    val assertion = createAssertion(alg, credentialKey = keypair)

    s"""
    |val keyAlgorithm: COSEAlgorithmIdentifier = COSEAlgorithmIdentifier.${alg.name}
    |val authenticatorData: ByteArray = ByteArray.fromHex("${assertion.getResponse.getAuthenticatorData.getHex}")
    |val clientDataJson: String = "\""${new String(
      assertion.getResponse.getClientDataJSON.getBytes,
      StandardCharsets.UTF_8,
    )}""\"
    |val credentialId: ByteArray = ByteArray.fromBase64Url("${assertion.getId.getBase64Url}")
    |val credentialKey: KeyPair = TestAuthenticator.importEcKeypair(
    |  privateBytes = ByteArray.fromHex("${new ByteArray(
      keypair.getPrivate.getEncoded
    ).getHex}"),
    |  publicBytes = ByteArray.fromHex("${new ByteArray(
      keypair.getPublic.getEncoded
    ).getHex}")
    |)
    |val signature: ByteArray = ByteArray.fromHex("${assertion.getResponse.getSignature.getHex}")
    """.stripMargin
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
      .userHandle(userHandle.asJava)
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
            case AttestationCert(cert, _, _, chain) =>
              Map(
                "x5c" -> f
                  .arrayNode()
                  .addAll(
                    (cert +: chain)
                      .map(crt => f.binaryNode(crt.getEncoded))
                      .asJava
                  )
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
      .setAll(
        Map(
          "alg" -> f.textNode("RS256"),
          "x5c" -> f
            .arrayNode()
            .addAll(
              (cert.cert +: cert.chain)
                .map(crt => f.textNode(new ByteArray(crt.getEncoded).getBase64))
                .asJava
            ),
        ).asJava
      )
    val jwsHeaderBase64 = new ByteArray(
      JacksonCodecs.json().writeValueAsBytes(jwsHeader)
    ).getBase64Url

    val jwsPayload = f
      .objectNode()
      .setAll(
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
      .setAll(
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

    g.initialize(ecSpec, new SecureRandom())

    g.generateKeyPair()
  }

  def generateEddsaKeypair(): KeyPair = {
    val alg = "Ed25519"
    val keyPairGenerator = KeyPairGenerator.getInstance(alg)
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
    g.initialize(2048, new SecureRandom())
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
      ),
      actualKeypair.getPrivate,
    )
  }

  private def buildCertificate(
      publicKey: PublicKey,
      issuerName: X500Name,
      subjectName: X500Name,
      signingKey: PrivateKey,
      signingAlg: COSEAlgorithmIdentifier,
      isCa: Boolean = false,
      extensions: Iterable[(String, Boolean, ASN1Primitive)],
  ): X509Certificate = {
    CertificateParser.parseDer({
      val builder = new X509v3CertificateBuilder(
        issuerName,
        new BigInteger("1337"),
        Date.from(Instant.parse("2018-09-06T17:42:00Z")),
        Date.from(Instant.parse("2018-09-06T17:42:00Z")),
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

  def generateRsaCertificate(): (X509Certificate, PrivateKey) =
    generateAttestationCertificate(COSEAlgorithmIdentifier.RS256)

  def importCertAndKeyFromPem(
      certPem: InputStream,
      keyPem: InputStream,
  ): (X509Certificate, PrivateKey) = {
    val cert: X509Certificate = Util.importCertFromPem(certPem)

    val priKeyParser = new PEMParser(
      new BufferedReader(new InputStreamReader(keyPem))
    )
    priKeyParser.readObject() // Throw away the EC params part

    val converter = new JcaPEMKeyConverter()

    val key: PrivateKey = converter
      .getKeyPair(
        priKeyParser
          .readObject()
          .asInstanceOf[PEMKeyPair]
      )
      .getPrivate

    (cert, key)
  }

  def coseAlgorithmOfJavaKey(key: PrivateKey): COSEAlgorithmIdentifier =
    Try(COSEAlgorithmIdentifier.valueOf(key.getAlgorithm)) getOrElse
      key match {
      case key: BCECPrivateKey =>
        key.getParameters.getCurve match {
          case _: SecP256R1Curve => COSEAlgorithmIdentifier.valueOf("ES256")
        }
    }

}
