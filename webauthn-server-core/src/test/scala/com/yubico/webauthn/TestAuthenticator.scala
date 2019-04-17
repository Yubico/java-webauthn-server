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

import java.io.InputStream
import java.io.BufferedReader
import java.io.InputStreamReader
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.PrivateKey
import java.security.Signature
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.KeyPair
import java.security.PublicKey
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.spec.ECPublicKeySpec
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.ECPoint
import java.security.spec.X509EncodedKeySpec
import java.time.Instant
import java.util.Base64
import java.util.Date

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.JsonNodeFactory
import com.fasterxml.jackson.databind.node.ObjectNode
import com.yubico.internal.util.CertificateParser
import com.yubico.internal.util.BinaryUtil
import com.yubico.internal.util.WebAuthnCodecs
import com.yubico.internal.util.scala.JavaConverters._
import com.yubico.webauthn.data.COSEAlgorithmIdentifier
import com.yubico.webauthn.data.AuthenticatorData
import com.yubico.webauthn.data.PublicKeyCredential
import com.yubico.webauthn.data.AuthenticatorAttestationResponse
import com.yubico.webauthn.data.PublicKeyCredentialParameters
import com.yubico.webauthn.data.ByteArray
import com.yubico.webauthn.data.UserIdentity
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions
import com.yubico.webauthn.data.AuthenticatorAssertionResponse
import com.yubico.webauthn.data.RelyingPartyIdentity
import com.yubico.webauthn.data.ClientRegistrationExtensionOutputs
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs
import com.yubico.webauthn.test.Util
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.ASN1Primitive
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX500NameUtil
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.spec.ECNamedCurveSpec
import org.bouncycastle.math.ec.custom.sec.SecP256R1Curve
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder

import scala.collection.JavaConverters._
import scala.util.Try


object TestAuthenticator {

  def main(args: Array[String]): Unit = {
    val attestationCertBytes: ByteArray = ByteArray.fromHex("308201313081d8a003020102020441c4567d300a06082a8648ce3d0403023021311f301d0603550403131646697265666f782055324620536f667420546f6b656e301e170d3137303930353134303030345a170d3137303930373134303030345a3021311f301d0603550403131646697265666f782055324620536f667420546f6b656e3059301306072a8648ce3d020106082a8648ce3d03010703420004f9b7dfc17c8a7dcaacdaaad402c7f1f8570e3e9165f6ce2b9b9a4f64333405e1b952c516560bbe7d304d2da3b6582734dadd980e379b0f86a3e42cc657cffe84300a06082a8648ce3d0403020348003045022067fd4da98db1ddbcef53041d3cfd15ed6b8315cb4116889c2eabe6b50b7f985f02210098842f6835ee18181acc765f642fa124556121f418e108c5ec1bb22e9c28b76b")
    val publicKeyHex: String = "04f9b7dfc17c8a7dcaacdaaad402c7f1f8570e3e9165f6ce2b9b9a4f64333405e1b952c516560bbe7d304d2da3b6582734dadd980e379b0f86a3e42cc657cffe84"
    val signedDataBytes: ByteArray = ByteArray.fromHex("0049960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d976354543ac68315afe4cd7947adf5f7e8e7dc87ddf4582ef6e7fb467e5cad098af50008f926c96b3248cb3733c70a10e3e0995af0892220d6293780335390594e35a73a3743ed97c8e4fd9c0e183d60ccb764edac2fcbdb84b6b940089be98744673db427ce9d4f09261d4f6535bf52dcd216d9ba81a88f2ed5d7fa04bb25e641a3cd7ef9922fdb8d7d4b9f81a55f661b74f26d97a9382dda9a6b62c378cf6603b9f1218a87c158d88bf1ac51b0e4343657de0e9a6b6d60289fed2b46239abe00947e6a04c6733148283cb5786a678afc959262a71be0925da9992354ba6438022d68ae573285e5564196d62edfc46432cba9393c6138882856a0296b41f5b4b97e00e935")
    val signatureBytes: ByteArray = ByteArray.fromHex("3046022100a78ca2cb9feb402acc9f50d16d96487821122bbbdf70c8745a6d37161a16de09022100e10db1bf39b73b18acf9236f758558a7811e04a7901d12f7f34f503b171fe51e")

    verifyU2fExampleWithCert(attestationCertBytes, signedDataBytes, signatureBytes)
    verifyU2fExampleWithExplicitParams(publicKeyHex, signedDataBytes, signatureBytes)

    println(generateAttestationCertificate())

    val (credential, _) = createBasicAttestedCredential(attestationStatementFormat = "packed")

    println(credential)
    println(s"Client data: ${new String(credential.getResponse.getClientDataJSON.getBytes, "UTF-8")}")
    println(s"Client data: ${credential.getResponse.getClientDataJSON.getHex}")
    println(s"Client data: ${credential.getResponse.getClientData}")
    println(s"Attestation object: ${credential.getResponse.getAttestationObject.getHex}")
    println(s"Attestation object: ${credential.getResponse.getAttestation}")

    println("Javascript:")
    println(s"""parseCreateCredentialResponse({ response: { attestationObject: new Buffer("${credential.getResponse.getAttestationObject.getHex}", 'hex'), clientDataJSON: new Buffer("${credential.getResponse.getClientDataJSON.getHex}", 'hex') } })""")

    println(s"Public key: ${BinaryUtil.toHex(Defaults.credentialKey.getPublic.getEncoded)}")
    println(s"Private key: ${BinaryUtil.toHex(Defaults.credentialKey.getPrivate.getEncoded)}")

    val assertion = createAssertion()
    println(s"Assertion signature: ${assertion.getResponse.getSignature.getHex}")
    println(s"Authenticator data: ${assertion.getResponse.getAuthenticatorData.getHex}")
    println(s"Client data: ${assertion.getResponse.getClientDataJSON.getHex}")
    println(s"Client data: ${new String(assertion.getResponse.getClientDataJSON.getBytes, "UTF-8")}")
  }

  val crypto = new BouncyCastleCrypto
  val javaCryptoProvider: java.security.Provider = crypto.getProvider

  object Defaults {
    val aaguid: ByteArray = new ByteArray(Array(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15))
    val challenge: ByteArray = new ByteArray(Array(0, 1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 16, 105, 121, 98, 91))
    val credentialId: ByteArray = new ByteArray(((0 to 31).toVector map { _.toByte }).toArray)
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
  private def toJson(node: JsonNode): String = new ObjectMapper().writeValueAsString(node)
  private def sha256(s: String): ByteArray = sha256(toBytes(s))
  private def sha256(b: ByteArray): ByteArray = new ByteArray(MessageDigest.getInstance("SHA-256", javaCryptoProvider).digest(b.getBytes))

  def makeCreateCredentialExample(publicKeyCredential: PublicKeyCredential[AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs]): String =
    s"""Attestation object: ${publicKeyCredential.getResponse.getAttestationObject.getHex}
      |Client data: ${publicKeyCredential.getResponse.getClientDataJSON.getHex}
    """.stripMargin

  private def createCredential(
    aaguid: ByteArray = Defaults.aaguid,
    alg: Option[COSEAlgorithmIdentifier] = None,
    attestationCertAndKey: Option[(X509Certificate, PrivateKey)] = None,
    attestationStatementFormat: String = "fido-u2f",
    authenticatorExtensions: Option[JsonNode] = None,
    challenge: ByteArray = Defaults.challenge,
    clientData: Option[JsonNode] = None,
    clientExtensions: ClientRegistrationExtensionOutputs = ClientRegistrationExtensionOutputs.builder().build(),
    credentialKeypair: Option[KeyPair] = None,
    origin: String = Defaults.origin,
    rpId: String = Defaults.rpId,
    safetynetCtsProfileMatch: Boolean = true,
    tokenBindingStatus: String = Defaults.TokenBinding.status,
    tokenBindingId: Option[String] = Defaults.TokenBinding.id,
    userId: UserIdentity = UserIdentity.builder().name("Test").displayName("Test").id(new ByteArray(Array(42, 13, 37))).build(),
    useSelfAttestation: Boolean = false
  ): data.PublicKeyCredential[data.AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs] = {

    val options = PublicKeyCredentialCreationOptions.builder()
      .rp(RelyingPartyIdentity.builder().id(rpId).name("Test party").build())
      .user(userId)
      .challenge(challenge)
      .pubKeyCredParams(List(PublicKeyCredentialParameters.builder().alg(COSEAlgorithmIdentifier.ES256).build()).asJava)
      .build()

    val clientDataJson: String = WebAuthnCodecs.json.writeValueAsString(clientData getOrElse {
      val json: ObjectNode = jsonFactory.objectNode()

      json.setAll(Map(
        "challenge" -> jsonFactory.textNode(challenge.getBase64Url),
        "origin" -> jsonFactory.textNode(origin),
        "type" -> jsonFactory.textNode("webauthn.create")
      ).asJava)

      json.set(
        "tokenBinding",
        {
          val tokenBinding = jsonFactory.objectNode()
          tokenBinding.set("status", jsonFactory.textNode(tokenBindingStatus))
          tokenBindingId foreach { id => tokenBinding.set("id", jsonFactory.textNode(id)) }
          tokenBinding
        }
      )

      json.set("clientExtensions", WebAuthnCodecs.json().readTree(WebAuthnCodecs.json().writeValueAsString(clientExtensions)))
      authenticatorExtensions foreach { extensions => json.set("authenticatorExtensions", extensions) }

      json
    })
    val clientDataJsonBytes = toBytes(clientDataJson)

    val authDataBytes: ByteArray = makeAuthDataBytes(
      rpId = Defaults.rpId,
      attestedCredentialDataBytes = Some(makeAttestedCredentialDataBytes(
        aaguid = aaguid,
        publicKeyCose = WebAuthnCodecs.ecPublicKeyToCose(credentialKeypair.getOrElse(generateEcKeypair()).getPublic.asInstanceOf[ECPublicKey]),
        rpId = Defaults.rpId
      ))
    )

    val attestationObjectBytes = makeAttestationObjectBytes(
      authDataBytes,
      attestationStatementFormat,
      clientDataJson,
      attestationCertAndKey,
      selfAttestationKey = if (useSelfAttestation) Some(credentialKeypair.get.getPrivate) else None,
      alg = alg,
      safetynetCtsProfileMatch = safetynetCtsProfileMatch
    )

    val response = AuthenticatorAttestationResponse.builder()
      .attestationObject(attestationObjectBytes)
      .clientDataJSON(clientDataJsonBytes)
      .build()

    PublicKeyCredential.builder()
      .id(response.getAttestation.getAuthenticatorData.getAttestedCredentialData.get.getCredentialId)
      .response(response)
      .clientExtensionResults(clientExtensions)
      .build()
  }

  def createBasicAttestedCredential(
    aaguid: ByteArray = Defaults.aaguid,
    attestationCertAndKey: Option[(X509Certificate, PrivateKey)] = None,
    attestationStatementFormat: String = "fido-u2f",
    generateRsaCert: Boolean = false,
    certSubject: Option[X500Name] = None,
    safetynetCtsProfileMatch: Boolean = true
  ): (data.PublicKeyCredential[data.AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs], Option[X509Certificate]) = {
    val (caCert, generatedAttestationCertAndKey) = attestationCertAndKey match {
      case None =>
        val (caCert, caKey) = generateAttestationCaCertificate()
        (
          Some(caCert),
          Some(
            certSubject match {
              case Some(name) => generateAttestationCertificate(caCertAndKey = Some((caCert, caKey)), generateRsa = generateRsaCert, name = name)
              case None => generateAttestationCertificate(caCertAndKey = Some((caCert, caKey)), generateRsa = generateRsaCert)
            }
          )
        )
      case Some(_) => (None, None)
    }

    (
      createCredential(
        aaguid = aaguid,
        attestationCertAndKey = attestationCertAndKey orElse generatedAttestationCertAndKey,
        attestationStatementFormat = attestationStatementFormat,
        safetynetCtsProfileMatch = safetynetCtsProfileMatch
      ),
      caCert
    )
  }

  def createSelfAttestedCredential(
    attestationStatementFormat: String = "fido-u2f",
    alg: Option[COSEAlgorithmIdentifier] = None
  ): (data.PublicKeyCredential[data.AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs], Option[Nothing]) = {
    val keypair = generateEcKeypair()
    (
      attestationStatementFormat match {
        case "fido-u2f" =>
          createCredential(
            attestationCertAndKey = Some(generateAttestationCertificate (keypair) ),
            attestationStatementFormat = attestationStatementFormat,
            credentialKeypair = Some(keypair),
            alg = alg
          )
        case "packed" =>
          createCredential(
            attestationCertAndKey = None,
            attestationStatementFormat = attestationStatementFormat,
            credentialKeypair = Some(keypair),
            useSelfAttestation = true,
            alg = alg
          )
      },
      None
    )
  }

  def createUnattestedCredential(): (PublicKeyCredential[AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs], Option[X509Certificate]) =
    (createCredential(attestationStatementFormat = "none"), None)

  def createAssertion(
    authenticatorExtensions: Option[JsonNode] = None,
    challenge: ByteArray = Defaults.challenge,
    clientData: Option[JsonNode] = None,
    clientExtensions: ClientAssertionExtensionOutputs = ClientAssertionExtensionOutputs.builder().build(),
    credentialId: ByteArray = Defaults.credentialId,
    credentialKey: KeyPair = Defaults.credentialKey,
    origin: String = Defaults.origin,
    rpId: String = Defaults.rpId,
    tokenBindingStatus: String = Defaults.TokenBinding.status,
    tokenBindingId: Option[String] = Defaults.TokenBinding.id,
    userHandle: Option[ByteArray] = None
  ): data.PublicKeyCredential[data.AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs] = {

    val clientDataJson: String = WebAuthnCodecs.json.writeValueAsString(clientData getOrElse {
      val json: ObjectNode = jsonFactory.objectNode()

      json.setAll(Map(
        "challenge" -> jsonFactory.textNode(challenge.getBase64Url),
        "origin" -> jsonFactory.textNode(origin),
        "type" -> jsonFactory.textNode("webauthn.get")
      ).asJava)

      json.set(
        "tokenBinding",
        {
          val tokenBinding = jsonFactory.objectNode()
          tokenBinding.set("status", jsonFactory.textNode(tokenBindingStatus))
          tokenBindingId foreach { id => tokenBinding.set("id", jsonFactory.textNode(id)) }
          tokenBinding
        }
      )

      json.set("clientExtensions", WebAuthnCodecs.json().readTree(WebAuthnCodecs.json().writeValueAsString(clientExtensions)))
      authenticatorExtensions foreach { extensions => json.set("authenticatorExtensions", extensions) }

      json
    })
    val clientDataJsonBytes = toBytes(clientDataJson)

    val authDataBytes: ByteArray = makeAuthDataBytes(rpId = Defaults.rpId)

    val response = AuthenticatorAssertionResponse.builder()
      .authenticatorData(authDataBytes)
      .clientDataJSON(clientDataJsonBytes)
      .signature(
        makeAssertionSignature(
          authDataBytes,
          crypto.hash(clientDataJsonBytes),
          credentialKey.getPrivate
        )
      )
      .userHandle(userHandle.asJava)
      .build()

    PublicKeyCredential.builder()
      .id(credentialId)
      .response(response)
      .clientExtensionResults(clientExtensions)
      .build()
  }

  def makeAttestationObjectBytes(
    authDataBytes: ByteArray,
    format: String,
    clientDataJson: String,
    certAndKey: Option[(X509Certificate, PrivateKey)],
    selfAttestationKey: Option[PrivateKey] = None,
    alg: Option[COSEAlgorithmIdentifier] = None,
    safetynetCtsProfileMatch: Boolean = true
  ): ByteArray = {
    val makeAttestationStatement: (ByteArray, String, Option[(X509Certificate, PrivateKey)]) => JsonNode = format match {
      case "android-safetynet" => makeAndroidSafetynetAttestationStatement(_, _, _, ctsProfileMatch = safetynetCtsProfileMatch)
      case "fido-u2f" => makeU2fAttestationStatement
      case "none" => makeNoneAttestationStatement
      case "packed" => makePackedAttestationStatement(_, _, _, selfAttestationKey = selfAttestationKey, alg = alg)
    }

    val f = JsonNodeFactory.instance
    val attObj = f.objectNode().setAll(Map(
      "authData" -> f.binaryNode(authDataBytes.getBytes),
      "fmt" -> f.textNode(format),
      "attStmt" -> makeAttestationStatement(authDataBytes, clientDataJson, certAndKey)
    ).asJava)

    new ByteArray(WebAuthnCodecs.cbor.writeValueAsBytes(attObj))
  }

  def makeU2fAttestationStatement(
    authDataBytes: ByteArray,
    clientDataJson: String,
    attestationCertAndKey: Option[(X509Certificate, PrivateKey)] = None
  ): JsonNode = {
    val (cert, key) = attestationCertAndKey getOrElse generateAttestationCertificate()
    val authData = new AuthenticatorData(authDataBytes)
    val signedData = makeU2fSignedData(
      authData.getRpIdHash,
      clientDataJson,
      authData.getAttestedCredentialData.get.getCredentialId,
      WebAuthnCodecs.ecPublicKeyToRaw(WebAuthnCodecs.importCosePublicKey(authData.getAttestedCredentialData.get.getCredentialPublicKey).asInstanceOf[ECPublicKey])
    )

    val f = JsonNodeFactory.instance
    f.objectNode().setAll(Map(
      "x5c" -> f.arrayNode().add(f.binaryNode(cert.getEncoded)),
      "sig" -> f.binaryNode(
        sign(
          signedData,
          key
        ).getBytes
      )
    ).asJava)
  }

  def makeNoneAttestationStatement(
    authDataBytes: ByteArray,
    clientDataJson: String,
    attestationCertAndKey: Option[(X509Certificate, PrivateKey)] = None
  ): JsonNode = JsonNodeFactory.instance.objectNode()

  def makeU2fSignedData(
    rpIdHash: ByteArray,
    clientDataJson: String,
    credentialId: ByteArray,
    credentialPublicKeyRawBytes: ByteArray
  ): ByteArray = {
    new ByteArray((Vector[Byte](0)
      ++ rpIdHash.getBytes
      ++ crypto.hash(clientDataJson).getBytes
      ++ credentialId.getBytes
      ++ credentialPublicKeyRawBytes.getBytes
    ).toArray)
  }

  def makePackedAttestationStatement(
    authDataBytes: ByteArray,
    clientDataJson: String,
    attestationCertAndKey: Option[(X509Certificate, PrivateKey)] = None,
    selfAttestationKey: Option[PrivateKey] = None,
    alg: Option[COSEAlgorithmIdentifier] = None
  ): JsonNode = {
    val (cert, key) = selfAttestationKey match {
      case Some(key) => (null, key)
      case None => attestationCertAndKey getOrElse generateAttestationCertificate()
    }

    val signedData = new ByteArray(authDataBytes.getBytes ++ crypto.hash(clientDataJson).getBytes)
    val signature = sign(signedData, key)

    val f = JsonNodeFactory.instance
    f.objectNode().setAll(
      (
        Map("sig" -> f.binaryNode(signature.getBytes))
          ++ (
            selfAttestationKey match {
              case Some(key) => Map("alg" -> f.numberNode((alg getOrElse coseAlgorithmOfJavaKey(key)).getId))
              case None => Map("x5c" -> f.arrayNode().add(f.binaryNode(cert.getEncoded)))
            }
          )
      ).asJava
    )
  }

  def makeAndroidSafetynetAttestationStatement(
    authDataBytes: ByteArray,
    clientDataJson: String,
    attestationCertAndKey: Option[(X509Certificate, PrivateKey)] = None,
    ctsProfileMatch: Boolean = true
  ): JsonNode = {
    val (cert, key) = attestationCertAndKey getOrElse generateAttestationCertificate()

    val nonce = crypto.hash(authDataBytes concat crypto.hash(clientDataJson))

    val f = JsonNodeFactory.instance

    val jwsHeader = f.objectNode().setAll(Map(
      "alg" -> f.textNode("RS256"),
      "x5c" -> f.arrayNode().add(f.textNode(new ByteArray(cert.getEncoded).getBase64))
    ).asJava)
    val jwsHeaderBase64 = new ByteArray(WebAuthnCodecs.json().writeValueAsBytes(jwsHeader)).getBase64Url

    val jwsPayload = f.objectNode().setAll(Map(
      "nonce" -> f.binaryNode(nonce.getBytes),
      "timestampMs" -> f.numberNode(Instant.now().toEpochMilli),
      "apkPackageName" -> f.textNode("com.yubico.webauthn.test"),
      "apkDigestSha256" -> f.textNode(crypto.hash("foo").getBase64),
      "ctsProfileMatch" -> f.booleanNode(ctsProfileMatch),
      "aplCertificateDigestSha256" -> f.arrayNode().add(f.textNode(crypto.hash("foo").getBase64)),
      "basicIntegrity" -> f.booleanNode(true)
    ).asJava)
    val jwsPayloadBase64 = new ByteArray(WebAuthnCodecs.json().writeValueAsBytes(jwsPayload)).getBase64Url

    val jwsSignedCompact = jwsHeaderBase64 + "." + jwsPayloadBase64
    val jwsSignedBytes = new ByteArray(jwsSignedCompact.getBytes(StandardCharsets.UTF_8))
    val jwsSignature = sign(jwsSignedBytes, key)

    val jwsCompact = jwsSignedCompact + "." + jwsSignature.getBase64Url

    val attStmt = f.objectNode().setAll(Map(
      "ver" -> f.textNode("14799021"),
      "response" -> f.binaryNode(jwsCompact.getBytes(StandardCharsets.UTF_8))
    ).asJava)

    attStmt
  }

  def makeAuthDataBytes(
    rpId: String = Defaults.rpId,
    counterBytes: ByteArray = ByteArray.fromHex("00000539"),
    attestedCredentialDataBytes: Option[ByteArray] = None,
    extensionsCborBytes: Option[ByteArray] = None
  ): ByteArray =
    new ByteArray((Vector[Byte]()
      ++ sha256(rpId).getBytes.toVector
      ++ Some[Byte]((0x01 | (if (attestedCredentialDataBytes.isDefined) 0x40 else 0x00) | (if (extensionsCborBytes.isDefined) 0x80 else 0x00)).toByte)
      ++ counterBytes.getBytes.toVector
      ++ (attestedCredentialDataBytes map { _.getBytes.toVector } getOrElse Nil)
      ++ (extensionsCborBytes map { _.getBytes.toVector } getOrElse Nil)
      ).toArray)

  def makeAttestedCredentialDataBytes(
    publicKeyCose: ByteArray,
    rpId: String = Defaults.rpId,
    counterBytes: ByteArray = ByteArray.fromHex("0539"),
    aaguid: ByteArray = Defaults.aaguid
  ): ByteArray = {
    val credentialId = sha256(publicKeyCose)

    new ByteArray((Vector[Byte]()
      ++ aaguid.getBytes.toVector
      ++ BinaryUtil.fromHex("0020").toVector
      ++ credentialId.getBytes.toVector
      ++ publicKeyCose.getBytes.toVector
    ).toArray)
  }

  def makeAssertionSignature(authenticatorData: ByteArray, clientDataHash: ByteArray, key: PrivateKey): ByteArray =
    sign(authenticatorData.concat(clientDataHash), key)

  def sign(data: ByteArray, key: PrivateKey): ByteArray = {
    val sig = Signature.getInstance("SHA256with" + key.getAlgorithm, javaCryptoProvider)
    sig.initSign(key)
    sig.update(data.getBytes)
    new ByteArray(sig.sign())
  }

  def generateEcKeypair(curve: String = "P-256"): KeyPair = {
    val ecSpec  = ECNamedCurveTable.getParameterSpec(curve)
    val g: KeyPairGenerator = KeyPairGenerator.getInstance("ECDSA", javaCryptoProvider)
    g.initialize(ecSpec, new SecureRandom())

    g.generateKeyPair()
  }

  def importEcKeypair(privateBytes: ByteArray, publicBytes: ByteArray): KeyPair = {
    val keyFactory: KeyFactory = KeyFactory.getInstance("ECDSA", javaCryptoProvider)
    new KeyPair(
      keyFactory.generatePublic(new X509EncodedKeySpec(publicBytes.getBytes)),
      keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateBytes.getBytes))
    )
  }

  def generateRsaKeypair(): KeyPair = {
    val g: KeyPairGenerator = KeyPairGenerator.getInstance("RSA", javaCryptoProvider)
    g.initialize(2048, new SecureRandom())
    g.generateKeyPair()
  }

  def verifySignature(
    pubKey: PublicKey,
    signedDataBytes: ByteArray,
    signatureBytes: ByteArray
  ): Boolean = {
    val sig: Signature = Signature.getInstance("SHA256withECDSA", javaCryptoProvider)
    sig.initVerify(pubKey)
    sig.update(signedDataBytes.getBytes)

    sig.verify(signatureBytes.getBytes) &&
      crypto.verifySignature(pubKey, signedDataBytes, signatureBytes)
  }

  def verifyU2fExampleWithCert(
    attestationCertBytes: ByteArray,
    signedDataBytes: ByteArray,
    signatureBytes: ByteArray
  ): Unit = {
    val attestationCert: X509Certificate  = CertificateParser.parseDer(attestationCertBytes.getBytes)
    val pubKey: PublicKey = attestationCert.getPublicKey
    verifySignature(pubKey, signedDataBytes, signatureBytes)
  }

  def verifyU2fExampleWithExplicitParams(
    publicKeyHex: String,
    signedDataBytes: ByteArray,
    signatureBytes: ByteArray
  ): Unit = {
    val pubKeyPoint = new ECPoint(new BigInteger(publicKeyHex drop 2 take 64, 16), new BigInteger(publicKeyHex drop 2 drop 64, 16))
    val namedSpec = ECNamedCurveTable.getParameterSpec("P-256")
    val curveSpec: ECNamedCurveSpec = new ECNamedCurveSpec("P-256", namedSpec.getCurve, namedSpec.getG, namedSpec.getN)
    val pubKeySpec: ECPublicKeySpec = new ECPublicKeySpec(pubKeyPoint, curveSpec)
    val pubKey: PublicKey = KeyFactory.getInstance("ECDSA", javaCryptoProvider).generatePublic(pubKeySpec)
    verifySignature(pubKey, signedDataBytes, signatureBytes)
  }

  def generateAttestationCaCertificate(
    keypair: KeyPair = generateEcKeypair(),
    name: X500Name = new X500Name("CN=Yubico WebAuthn unit tests CA, O=Yubico, OU=Authenticator Attestation, C=SE"),
    superCa: Option[(X509Certificate, PrivateKey)] = None,
    extensions: Iterable[(String, Boolean, ASN1Primitive)] = Nil
  ): (X509Certificate, PrivateKey) = {
    (
      buildCertificate(
        publicKey = keypair.getPublic,
        issuerName = superCa map (_._1) map JcaX500NameUtil.getSubject getOrElse name,
        subjectName = name,
        signingKey = superCa map (_._2) getOrElse keypair.getPrivate,
        isCa = true,
        extensions = extensions
      ),
      keypair.getPrivate
    )
  }

  def generateAttestationCertificate(
    keypair: KeyPair = generateEcKeypair(),
    name: X500Name = new X500Name("CN=Yubico WebAuthn unit tests, O=Yubico, OU=Authenticator Attestation, C=SE"),
    extensions: Iterable[(String, Boolean, ASN1Primitive)] = List(("1.3.6.1.4.1.45724.1.1.4", false, new DEROctetString(Defaults.aaguid.getBytes))),
    caCertAndKey: Option[(X509Certificate, PrivateKey)] = None,
    generateRsa: Boolean = false
  ): (X509Certificate, PrivateKey) = {
    val actualKeypair =
      if (generateRsa) generateRsaKeypair()
      else keypair

    (
      buildCertificate(
        publicKey = actualKeypair.getPublic,
        issuerName = caCertAndKey.map(_._1).map(JcaX500NameUtil.getSubject).getOrElse(name),
        subjectName = name,
        signingKey = caCertAndKey.map(_._2).getOrElse(actualKeypair.getPrivate),
        isCa = false,
        extensions = extensions
      ),
      actualKeypair.getPrivate
    )
  }

  private def buildCertificate(
    publicKey: PublicKey,
    issuerName: X500Name,
    subjectName: X500Name,
    signingKey: PrivateKey,
    isCa: Boolean = false,
    extensions: Iterable[(String, Boolean, ASN1Primitive)] = Nil
  ): X509Certificate = {
    CertificateParser.parseDer({
      val builder = new X509v3CertificateBuilder(
        issuerName,
        new BigInteger("1337"),
        Date.from(Instant.parse("2018-09-06T17:42:00Z")),
        Date.from(Instant.parse("2018-09-06T17:42:00Z")),
        subjectName,
        SubjectPublicKeyInfo.getInstance(publicKey.getEncoded)
      )

      for { (oid, critical, value) <- extensions } {
        builder.addExtension(new ASN1ObjectIdentifier(oid), critical, value)
      }

      if (isCa) {
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
      }

      builder.build(new JcaContentSignerBuilder("SHA256with" + signingKey.getAlgorithm).setProvider(javaCryptoProvider).build(signingKey)).getEncoded
    })
  }

  def generateRsaCertificate(): (X509Certificate, PrivateKey) =
    generateAttestationCertificate(keypair = generateRsaKeypair())

  def importCertAndKeyFromPem(certPem: InputStream, keyPem: InputStream): (X509Certificate, PrivateKey) = {
    val cert: X509Certificate = Util.importCertFromPem(certPem)

    val priKeyParser = new PEMParser(new BufferedReader(new InputStreamReader(keyPem)))
    priKeyParser.readObject() // Throw away the EC params part

    val key: PrivateKey = new JcaPEMKeyConverter().setProvider(javaCryptoProvider)
      .getKeyPair(
        priKeyParser.readObject()
          .asInstanceOf[PEMKeyPair]
      )
      .getPrivate

    (cert, key)
  }

  def toPem(cert: X509Certificate): String = (
    "-----BEGIN CERTIFICATE-----\n"
    + Base64.getMimeEncoder(64, System.getProperty("line.separator").getBytes("UTF-8"))
        .encodeToString(cert.getEncoded)
    + "\n-----END CERTIFICATE-----\n"
  )

  def coseAlgorithmOfJavaKey(key: PrivateKey): COSEAlgorithmIdentifier =
    Try(COSEAlgorithmIdentifier.valueOf(key.getAlgorithm)) getOrElse
        key match {
          case key: BCECPrivateKey => key.getParameters.getCurve match {
            case _: SecP256R1Curve => COSEAlgorithmIdentifier.valueOf("ES256")
          }
        }

}
