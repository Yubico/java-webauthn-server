package com.yubico.webauthn.test

import java.io.BufferedReader
import java.io.InputStreamReader
import java.io.InputStream
import java.math.BigInteger
import java.security.MessageDigest
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.KeyPair
import java.security.PublicKey
import java.security.Signature
import java.security.PrivateKey
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.spec.ECPublicKeySpec
import java.security.spec.ECPoint
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.time.Instant
import java.util.Date
import java.util.Base64

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.JsonNodeFactory
import com.fasterxml.jackson.databind.node.ObjectNode
import com.yubico.scala.util.JavaConverters._
import com.yubico.u2f.crypto.BouncyCastleCrypto
import com.yubico.u2f.crypto.Crypto
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding
import com.yubico.u2f.data.messages.key.util.CertificateParser
import com.yubico.webauthn.util
import com.yubico.webauthn.data
import com.yubico.webauthn.data.ArrayBuffer
import com.yubico.webauthn.data.AuthenticatorData
import com.yubico.webauthn.data.UserIdentity
import com.yubico.webauthn.data.PublicKeyCredentialParameters
import com.yubico.webauthn.data.PublicKeyCredential
import com.yubico.webauthn.data.AuthenticatorAttestationResponse
import com.yubico.webauthn.data.COSEAlgorithmIdentifier
import com.yubico.webauthn.data.AuthenticatorAssertionResponse
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions
import com.yubico.webauthn.data.RelyingPartyIdentity
import com.yubico.webauthn.util.WebAuthnCodecs
import com.yubico.webauthn.util.BinaryUtil
import org.bouncycastle.asn1.ASN1ObjectIdentifier
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.asn1.x509.BasicConstraints
import org.bouncycastle.asn1.x509.Extension
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.cert.jcajce.JcaX500NameUtil
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECNamedCurveSpec
import org.bouncycastle.openssl.PEMParser
import org.bouncycastle.openssl.PEMKeyPair
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder

import scala.collection.JavaConverters._

object TestAuthenticator {

  def main(args: Array[String]): Unit = {
    val attestationCertBytes: ArrayBuffer = BinaryUtil.fromHex("308201313081d8a003020102020441c4567d300a06082a8648ce3d0403023021311f301d0603550403131646697265666f782055324620536f667420546f6b656e301e170d3137303930353134303030345a170d3137303930373134303030345a3021311f301d0603550403131646697265666f782055324620536f667420546f6b656e3059301306072a8648ce3d020106082a8648ce3d03010703420004f9b7dfc17c8a7dcaacdaaad402c7f1f8570e3e9165f6ce2b9b9a4f64333405e1b952c516560bbe7d304d2da3b6582734dadd980e379b0f86a3e42cc657cffe84300a06082a8648ce3d0403020348003045022067fd4da98db1ddbcef53041d3cfd15ed6b8315cb4116889c2eabe6b50b7f985f02210098842f6835ee18181acc765f642fa124556121f418e108c5ec1bb22e9c28b76b").get
    val publicKeyHex: String = "04f9b7dfc17c8a7dcaacdaaad402c7f1f8570e3e9165f6ce2b9b9a4f64333405e1b952c516560bbe7d304d2da3b6582734dadd980e379b0f86a3e42cc657cffe84"
    val signedDataBytes: ArrayBuffer = BinaryUtil.fromHex("0049960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d976354543ac68315afe4cd7947adf5f7e8e7dc87ddf4582ef6e7fb467e5cad098af50008f926c96b3248cb3733c70a10e3e0995af0892220d6293780335390594e35a73a3743ed97c8e4fd9c0e183d60ccb764edac2fcbdb84b6b940089be98744673db427ce9d4f09261d4f6535bf52dcd216d9ba81a88f2ed5d7fa04bb25e641a3cd7ef9922fdb8d7d4b9f81a55f661b74f26d97a9382dda9a6b62c378cf6603b9f1218a87c158d88bf1ac51b0e4343657de0e9a6b6d60289fed2b46239abe00947e6a04c6733148283cb5786a678afc959262a71be0925da9992354ba6438022d68ae573285e5564196d62edfc46432cba9393c6138882856a0296b41f5b4b97e00e935").get
    val signatureBytes: ArrayBuffer = BinaryUtil.fromHex("3046022100a78ca2cb9feb402acc9f50d16d96487821122bbbdf70c8745a6d37161a16de09022100e10db1bf39b73b18acf9236f758558a7811e04a7901d12f7f34f503b171fe51e").get

    verifyU2fExampleWithCert(attestationCertBytes, signedDataBytes, signatureBytes)
    verifyU2fExampleWithExplicitParams(publicKeyHex, signedDataBytes, signatureBytes)

    println(generateAttestationCertificate())

    val (credential, _) = createBasicAttestedCredential(attestationStatementFormat = "packed")

    println(credential)
    println(s"Client data: ${new String(credential.response.clientDataJSON.toArray, "UTF-8")}")
    println(s"Client data: ${BinaryUtil.toHex(credential.response.clientDataJSON)}")
    println(s"Client data: ${credential.response.collectedClientData}")
    println(s"Attestation object: ${BinaryUtil.toHex(credential.response.attestationObject)}")
    println(s"Attestation object: ${credential.response.attestation}")

    println("Javascript:")
    println(s"""parseCreateCredentialResponse({ response: { attestationObject: new Buffer("${BinaryUtil.toHex(credential.response.attestationObject)}", 'hex'), clientDataJSON: new Buffer("${BinaryUtil.toHex(credential.response.clientDataJSON)}", 'hex') } })""")

    println(s"Public key: ${BinaryUtil.toHex(Defaults.credentialKey.getPublic.getEncoded.toVector)}")
    println(s"Private key: ${BinaryUtil.toHex(Defaults.credentialKey.getPrivate.getEncoded.toVector)}")

    val assertion = createAssertion()
    println(s"Assertion signature: ${BinaryUtil.toHex(assertion.response.signature)}")
    println(s"Authenticator data: ${BinaryUtil.toHex(assertion.response.authenticatorData)}")
    println(s"Client data: ${BinaryUtil.toHex(assertion.response.clientDataJSON)}")
    println(s"Client data: ${new String(assertion.response.clientDataJSON.toArray, "UTF-8")}")
  }

  val crypto: Crypto = new BouncyCastleCrypto
  val javaCryptoProvider: java.security.Provider = new BouncyCastleProvider()

  object Defaults {
    val aaguid: ArrayBuffer = Vector[Byte](0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15)
    val challenge: ArrayBuffer = Vector[Byte](0, 1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 16, 105, 121, 98, 91)
    val credentialId: ArrayBuffer = (0 to 31).toVector map { _.toByte }
    val rpId = "localhost"
    object TokenBinding {
      val status = "supported"
      val id = None
    }

    val credentialKey: KeyPair = generateEcKeypair()
  }

  private def jsonFactory: JsonNodeFactory = JsonNodeFactory.instance
  private def toBytes(s: String): Vector[Byte] = s.getBytes("UTF-8").toVector
  private def toJson(node: JsonNode): String = new ObjectMapper().writeValueAsString(node)
  private def sha256(s: String): Vector[Byte] = sha256(toBytes(s))
  private def sha256(b: Seq[Byte]): Vector[Byte] = MessageDigest.getInstance("SHA-256").digest(b.toArray).toVector

  def makeCreateCredentialExample(publicKeyCredential: PublicKeyCredential[AuthenticatorAttestationResponse]): String =
    s"""Attestation object: ${BinaryUtil.toHex(publicKeyCredential.response.attestationObject)}
      |Client data: ${BinaryUtil.toHex(publicKeyCredential.response.clientDataJSON)}
    """.stripMargin

  private def createCredential(
    aaguid: ArrayBuffer = Defaults.aaguid,
    alg: Option[COSEAlgorithmIdentifier] = None,
    attestationCertAndKey: Option[(X509Certificate, PrivateKey)] = None,
    attestationStatementFormat: String = "fido-u2f",
    authenticatorExtensions: Option[JsonNode] = None,
    challenge: ArrayBuffer = Defaults.challenge,
    clientData: Option[JsonNode] = None,
    clientExtensions: Option[JsonNode] = None,
    credentialKeypair: Option[KeyPair] = None,
    origin: String = Defaults.rpId,
    rpId: String = Defaults.rpId,
    tokenBindingStatus: String = Defaults.TokenBinding.status,
    tokenBindingId: Option[String] = Defaults.TokenBinding.id,
    userId: UserIdentity = UserIdentity(name = "Test", displayName = "Test", id = Vector(42, 13, 37)),
    useSelfAttestation: Boolean = false
  ): data.PublicKeyCredential[data.AuthenticatorAttestationResponse] = {

    val options = PublicKeyCredentialCreationOptions(
      rp = RelyingPartyIdentity(name = "Test party", id = rpId),
      user = userId ,
      challenge = challenge,
      pubKeyCredParams = List(PublicKeyCredentialParameters(alg = -7)).asJava
    )

    val challengeBase64 = U2fB64Encoding.encode(options.challenge.toArray)

    val clientDataJson: String = WebAuthnCodecs.json.writeValueAsString(clientData getOrElse {
      val json: ObjectNode = jsonFactory.objectNode()

      json.setAll(Map(
        "challenge" -> jsonFactory.textNode(challengeBase64),
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

      clientExtensions foreach { extensions => json.set("clientExtensions", extensions) }
      authenticatorExtensions foreach { extensions => json.set("authenticatorExtensions", extensions) }

      json
    })
    val clientDataJsonBytes = toBytes(clientDataJson)

    val authDataBytes: ArrayBuffer = makeAuthDataBytes(
      rpId = Defaults.rpId,
      attestationDataBytes = Some(makeAttestationDataBytes(
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
      alg = alg
    )

    val response = AuthenticatorAttestationResponse(
      attestationObject = attestationObjectBytes,
      clientDataJSON = clientDataJsonBytes
    )

    PublicKeyCredential(
      rawId = response.attestation.authenticatorData.attestationData.get.credentialId,
      response = response,
      clientExtensionResults = WebAuthnCodecs.json.readTree("{}")
    )
  }

  def createBasicAttestedCredential(
    aaguid: ArrayBuffer = Defaults.aaguid,
    attestationCertAndKey: Option[(X509Certificate, PrivateKey)] = None,
    attestationStatementFormat: String = "fido-u2f"
  ): (data.PublicKeyCredential[data.AuthenticatorAttestationResponse], Option[X509Certificate]) = {
    val (caCert, generatedAttestationCertAndKey) = attestationCertAndKey match {
      case None =>
        val (caCert, caKey) = generateAttestationCaCertificate()
        (Some(caCert), Some(generateAttestationCertificate(caCertAndKey = Some((caCert, caKey)))))
      case Some(_) => (None, None)
    }

    (
      createCredential(
        aaguid = aaguid,
        attestationCertAndKey = attestationCertAndKey orElse generatedAttestationCertAndKey,
        attestationStatementFormat = attestationStatementFormat
      ),
      caCert
    )
  }

  def createSelfAttestedCredential(
    attestationStatementFormat: String = "fido-u2f",
    alg: Option[COSEAlgorithmIdentifier] = None
  ): (data.PublicKeyCredential[data.AuthenticatorAttestationResponse], Option[Nothing]) = {
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

  def createUnattestedCredential(): (PublicKeyCredential[AuthenticatorAttestationResponse], Option[X509Certificate]) =
    (createCredential(attestationStatementFormat = "none"), None)

  def createAssertion(
    authenticatorExtensions: Option[JsonNode] = None,
    challenge: ArrayBuffer = Defaults.challenge,
    clientData: Option[JsonNode] = None,
    clientExtensions: Option[JsonNode] = None,
    credentialId: ArrayBuffer = Defaults.credentialId,
    credentialKey: KeyPair = Defaults.credentialKey,
    origin: String = Defaults.rpId,
    rpId: String = Defaults.rpId,
    tokenBindingStatus: String = Defaults.TokenBinding.status,
    tokenBindingId: Option[String] = Defaults.TokenBinding.id,
    userHandle: Option[ArrayBuffer] = None
  ): data.PublicKeyCredential[data.AuthenticatorAssertionResponse] = {

    val challengeBase64 = U2fB64Encoding.encode(challenge.toArray)

    val clientDataJson: String = WebAuthnCodecs.json.writeValueAsString(clientData getOrElse {
      val json: ObjectNode = jsonFactory.objectNode()

      json.setAll(Map(
        "challenge" -> jsonFactory.textNode(challengeBase64),
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

      clientExtensions foreach { extensions => json.set("clientExtensions", extensions) }
      authenticatorExtensions foreach { extensions => json.set("authenticatorExtensions", extensions) }

      json
    })
    val clientDataJsonBytes = toBytes(clientDataJson)

    val authDataBytes: ArrayBuffer = makeAuthDataBytes(rpId = Defaults.rpId)

    val response = AuthenticatorAssertionResponse(
      clientDataJSON = clientDataJsonBytes,
      authenticatorData = authDataBytes,
      signature = makeAssertionSignature(
        authDataBytes,
        crypto.hash(clientDataJsonBytes.toArray).toVector,
        credentialKey.getPrivate
      ),
      userHandle = userHandle.asJava
    )

    PublicKeyCredential(
      rawId = credentialId,
      response = response,
      clientExtensionResults = jsonFactory.objectNode()
    )

  }

  def makeAttestationObjectBytes(
    authDataBytes: ArrayBuffer,
    format: String,
    clientDataJson: String,
    certAndKey: Option[(X509Certificate, PrivateKey)],
    selfAttestationKey: Option[PrivateKey] = None,
    alg: Option[COSEAlgorithmIdentifier] = None
  ): ArrayBuffer = {
    val makeAttestationStatement: (ArrayBuffer, String, Option[(X509Certificate, PrivateKey)]) => JsonNode = format match {
      case "fido-u2f" => makeU2fAttestationStatement _
      case "none" => makeNoneAttestationStatement _
      case "packed" => makePackedAttestationStatement(_, _, _, selfAttestationKey = selfAttestationKey, alg = alg)
    }

    val f = JsonNodeFactory.instance
    val attObj = f.objectNode().setAll(Map(
      "authData" -> f.binaryNode(authDataBytes.toArray),
      "fmt" -> f.textNode(format),
      "attStmt" -> makeAttestationStatement(authDataBytes, clientDataJson, certAndKey)
    ).asJava)

    WebAuthnCodecs.cbor.writeValueAsBytes(attObj).toVector
  }

  def makeU2fAttestationStatement(
    authDataBytes: ArrayBuffer,
    clientDataJson: String,
    attestationCertAndKey: Option[(X509Certificate, PrivateKey)] = None
  ): JsonNode = {
    val (cert, key) = attestationCertAndKey getOrElse generateAttestationCertificate()
    val authData = AuthenticatorData(authDataBytes)
    val signedData = makeU2fSignedData(
      authData.rpIdHash,
      clientDataJson,
      authData.attestationData.get.credentialId,
      WebAuthnCodecs.ecPublicKeyToRaw(WebAuthnCodecs.importCoseP256PublicKey(authData.attestationData.get.credentialPublicKey))
    )

    val f = JsonNodeFactory.instance
    f.objectNode().setAll(Map(
      "x5c" -> f.arrayNode().add(f.binaryNode(cert.getEncoded)),
      "sig" -> f.binaryNode(
        sign(
          signedData,
          key
        ).toArray
      )
    ).asJava)
  }

  def makeNoneAttestationStatement(
    authDataBytes: ArrayBuffer,
    clientDataJson: String,
    attestationCertAndKey: Option[(X509Certificate, PrivateKey)] = None
  ): JsonNode = JsonNodeFactory.instance.objectNode()

  def makeU2fSignedData(
    rpIdHash: ArrayBuffer,
    clientDataJson: String,
    credentialId: ArrayBuffer,
    credentialPublicKeyRawBytes: ArrayBuffer
  ): ArrayBuffer = {
    (Vector[Byte](0)
      ++ rpIdHash
      ++ crypto.hash(clientDataJson)
      ++ credentialId
      ++ credentialPublicKeyRawBytes
    )
  }

  def makePackedAttestationStatement(
    authDataBytes: ArrayBuffer,
    clientDataJson: String,
    attestationCertAndKey: Option[(X509Certificate, PrivateKey)] = None,
    selfAttestationKey: Option[PrivateKey] = None,
    alg: Option[COSEAlgorithmIdentifier] = None
  ): JsonNode = {
    val (cert, key) = selfAttestationKey match {
      case Some(key) => (null, key)
      case None => attestationCertAndKey getOrElse generateAttestationCertificate()
    }

    val signedData = authDataBytes ++ crypto.hash(clientDataJson)
    val signature = sign(signedData, key)

    val f = JsonNodeFactory.instance
    f.objectNode().setAll(
      (
        Map("sig" -> f.binaryNode(signature.toArray))
          ++ (
            selfAttestationKey match {
              case Some(key) => Map("alg" -> f.numberNode(alg getOrElse WebAuthnCodecs.javaAlgorithmNameToCoseAlgorithmIdentifier(key.getAlgorithm)))
              case None => Map("x5c" -> f.arrayNode().add(f.binaryNode(cert.getEncoded)))
            }
          )
      ).asJava
    )
  }

  def makeAuthDataBytes(
    rpId: String = Defaults.rpId,
    counterBytes: ArrayBuffer = BinaryUtil.fromHex("00000539").get,
    attestationDataBytes: Option[ArrayBuffer] = None,
    extensionsCborBytes: Option[ArrayBuffer] = None
  ): ArrayBuffer =
    (Vector[Byte]()
      ++ sha256(rpId)
      ++ Some[Byte]((0x01 | (if (attestationDataBytes.isDefined) 0x40 else 0x00) | (if (extensionsCborBytes.isDefined) 0x80 else 0x00)).toByte)
      ++ counterBytes
      ++ (attestationDataBytes getOrElse Nil)
      ++ (extensionsCborBytes getOrElse Nil)
      )

  def makeAttestationDataBytes(
    publicKeyCose: ArrayBuffer,
    rpId: String = Defaults.rpId,
    counterBytes: ArrayBuffer = BinaryUtil.fromHex("0539").get,
    aaguid: ArrayBuffer = Defaults.aaguid
  ): ArrayBuffer = {
    val credentialId = sha256(publicKeyCose)

    (Vector[Byte]()
      ++ aaguid
      ++ util.BinaryUtil.fromHex("0020").get
      ++ credentialId
      ++ publicKeyCose
    )
  }

  def makeAssertionSignature(authenticatorData: ArrayBuffer, clientDataHash: ArrayBuffer, key: PrivateKey): ArrayBuffer =
    sign(authenticatorData ++ clientDataHash, key)

  def sign(data: ArrayBuffer, key: PrivateKey): ArrayBuffer = {
    val sig = Signature.getInstance("SHA256with" + key.getAlgorithm, javaCryptoProvider)
    sig.initSign(key)
    sig.update(data.toArray)
    sig.sign().toVector
  }

  def generateEcKeypair(curve: String = "P-256"): KeyPair = {
    val ecSpec  = ECNamedCurveTable.getParameterSpec(curve)
    val g: KeyPairGenerator = KeyPairGenerator.getInstance("ECDSA", javaCryptoProvider)
    g.initialize(ecSpec, new SecureRandom())

    g.generateKeyPair()
  }

  def importEcKeypair(privateBytes: ArrayBuffer, publicBytes: ArrayBuffer): KeyPair = {
    val keyFactory: KeyFactory = KeyFactory.getInstance("ECDSA", javaCryptoProvider)
    new KeyPair(
      keyFactory.generatePublic(new X509EncodedKeySpec(publicBytes.toArray)),
      keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateBytes.toArray))
    )
  }

  def generateRsaKeypair(): KeyPair = {
    val g: KeyPairGenerator = KeyPairGenerator.getInstance("RSA", javaCryptoProvider)
    g.initialize(2048, new SecureRandom())
    g.generateKeyPair()
  }

  def verifySignature(
    pubKey: PublicKey,
    signedDataBytes: ArrayBuffer,
    signatureBytes: ArrayBuffer
  ): Boolean = {
    val sig: Signature = Signature.getInstance("SHA256withECDSA", javaCryptoProvider)
    sig.initVerify(pubKey)
    sig.update(signedDataBytes.toArray)
    val valid = sig.verify(signatureBytes.toArray)
    crypto.checkSignature(pubKey, signedDataBytes.toArray, signatureBytes.toArray)

    valid
  }

  def verifyU2fExampleWithCert(
    attestationCertBytes: ArrayBuffer,
    signedDataBytes: ArrayBuffer,
    signatureBytes: ArrayBuffer
  ): Unit = {
    val attestationCert: X509Certificate  = CertificateParser.parseDer(attestationCertBytes.toArray)
    val pubKey: PublicKey = attestationCert.getPublicKey
    verifySignature(pubKey, signedDataBytes, signatureBytes)
  }

  def verifyU2fExampleWithExplicitParams(
    publicKeyHex: String,
    signedDataBytes: ArrayBuffer,
    signatureBytes: ArrayBuffer
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
    name: X500Name = new X500Name("CN=Yubico WebAuthn unit tests CA, O=Yubico, OU=Authenticator Attestation, C=SE")
  ): (X509Certificate, PrivateKey) = {
    (
      buildCertificate(
        publicKey = keypair.getPublic,
        issuerName = name,
        subjectName = name,
        signingKey = keypair.getPrivate,
        isCa = true
      ),
      keypair.getPrivate
    )
  }

  def generateAttestationCertificate(
    keypair: KeyPair = generateEcKeypair(),
    name: X500Name = new X500Name("CN=Yubico WebAuthn unit tests, O=Yubico, OU=Authenticator Attestation, C=SE"),
    extensions: Iterable[(String, Boolean, ArrayBuffer)] = List(("1.3.6.1.4.1.45724.1.1.4", false, Defaults.aaguid)),
    caCertAndKey: Option[(X509Certificate, PrivateKey)] = None
  ): (X509Certificate, PrivateKey) = {
    (
      buildCertificate(
        publicKey = keypair.getPublic,
        issuerName = caCertAndKey.map(_._1).map(JcaX500NameUtil.getSubject).getOrElse(name),
        subjectName = name,
        signingKey = caCertAndKey.map(_._2).getOrElse(keypair.getPrivate),
        isCa = false,
        extensions = extensions
      ),
      keypair.getPrivate
    )
  }

  private def buildCertificate(
    publicKey: PublicKey,
    issuerName: X500Name,
    subjectName: X500Name,
    signingKey: PrivateKey,
    isCa: Boolean = false,
    extensions: Iterable[(String, Boolean, ArrayBuffer)] = Nil
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
        builder.addExtension(new ASN1ObjectIdentifier(oid), critical, new DEROctetString(value.toArray))
      }

      if (isCa) {
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
      }

      builder.build(new JcaContentSignerBuilder("SHA256with" + signingKey.getAlgorithm).build(signingKey)).getEncoded
    })
  }

  def generateRsaCertificate(): (X509Certificate, PrivateKey) =
    generateAttestationCertificate(keypair = generateRsaKeypair())

  def importCertAndKeyFromPem(certPem: InputStream, keyPem: InputStream): (X509Certificate, PrivateKey) = {
    val cert: X509Certificate = Util.importCertFromPem(certPem)

    val priKeyParser = new PEMParser(new BufferedReader(new InputStreamReader(keyPem)))
    priKeyParser.readObject() // Throw away the EC params part

    val key: PrivateKey = new JcaPEMKeyConverter().setProvider(new BouncyCastleProvider)
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

}
