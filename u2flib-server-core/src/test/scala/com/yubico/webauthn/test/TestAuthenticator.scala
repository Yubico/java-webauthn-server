package com.yubico.webauthn.test

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
import java.security.spec.ECPublicKeySpec
import java.security.spec.ECPoint
import java.time.LocalDate
import java.time.ZoneId
import java.time.ZonedDateTime
import java.time.Instant
import java.util.Date
import javax.security.auth.x500.X500Principal

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.JsonNodeFactory
import com.yubico.u2f.crypto.BouncyCastleCrypto
import com.yubico.u2f.data.messages.key.util.CertificateParser
import com.yubico.webauthn.data
import com.yubico.webauthn.util
import com.yubico.webauthn.data.MakePublicKeyCredentialOptions
import com.yubico.webauthn.data.Base64UrlString
import com.yubico.webauthn.data.ArrayBuffer
import com.yubico.webauthn.util.WebAuthnCodecs
import com.yubico.webauthn.util.BinaryUtil
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers
import org.bouncycastle.asn1.x500.X500NameBuilder
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo
import org.bouncycastle.asn1.x509.AlgorithmIdentifier
import org.bouncycastle.cert.X509v3CertificateBuilder
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECNamedCurveSpec
import org.bouncycastle.operator.ContentSigner
import org.bouncycastle.operator.bc.BcECContentSignerBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder

import scala.collection.JavaConverters._

object TestAuthenticator {

  private val BcProvider = new BouncyCastleProvider()
  private val DefaultRpId = "localhost"

  private def toBytes(s: String): Vector[Byte] = s.getBytes("UTF-8").toVector
  private def toJson(node: JsonNode): String = new ObjectMapper().writeValueAsString(node)
  private def sha256(s: String): Vector[Byte] = sha256(toBytes(s))
  private def sha256(b: Seq[Byte]): Vector[Byte] = MessageDigest.getInstance("SHA-256").digest(b.toArray).toVector

  def createCredential(
    options: MakePublicKeyCredentialOptions,
    clientData: JsonNode,
    challengeBase64: Base64UrlString = "s1lKsm0KoJpzXM2YsHpOLQ",
    origin: String = DefaultRpId,
    tokenBindingId: Option[String] = None,
    clientExtensions: Option[JsonNode] = None,
    authenticatorExtensions: Option[JsonNode] = None,
  ): data.PublicKeyCredential[data.AuthenticatorAttestationResponse] = {

    val clientDataJsonBytes =
      toBytes(s"""{
        |"challenge": "${challengeBase64}",
        |"origin": "${origin}",
        |"hashAlgorithm": "SHA-256",
        |${tokenBindingId map { id => s""" "tokenBindingId": "${id}", """ } getOrElse "" },
        |"clientExtensions": ${clientExtensions map toJson getOrElse "{}"}",
        |"authenticatorExtensions": ${authenticatorExtensions map toJson getOrElse "{}"}
        |}
      """.stripMargin)

    val attestationObjectBytes = makeAttestationObjectBytes(
      makeAuthDataBytes(
        rpId = DefaultRpId,
        attestationDataBytes = Some(makeAttestationDataBytes(
          rpId = DefaultRpId,
        ))
      )
    )

    val response = data.impl.AuthenticatorAttestationResponse(
      attestationObject = attestationObjectBytes,
      clientDataJSON = clientDataJsonBytes,
    )

    data.impl.PublicKeyCredential(
      rawId = response.attestation.authenticatorData.attestationData.get.credentialId,
      response = response,
      clientExtensionResults = WebAuthnCodecs.json.readTree("{}")
    )
  }

  def makeAttestationObjectBytes(authDataBytes: ArrayBuffer): ArrayBuffer = {
    val format = "fido-u2f"
    val f = JsonNodeFactory.instance
    val attObj = f.objectNode().setAll(Map(
      "authData" -> f.binaryNode(authDataBytes.toArray),
      "fmt" -> f.textNode(format),
      "attStmt" -> makeU2fAttestationStatement(authDataBytes),
    ).asJava)

    WebAuthnCodecs.cbor.writeValueAsBytes(attObj).toVector
  }

  def makeU2fAttestationStatement(authDataBytes: ArrayBuffer): JsonNode = {
    val certDerBytes: ArrayBuffer = ???
    val signatureDerBytes: ArrayBuffer = ???

    val f = JsonNodeFactory.instance
    f.objectNode().setAll(Map(
      "x5c" -> f.binaryNode(certDerBytes.toArray),
      "sig" -> f.binaryNode(signatureDerBytes.toArray),
    ).asJava)
  }

  def makeAuthDataBytes(
    rpId: String = DefaultRpId,
    counterBytes: ArrayBuffer = BinaryUtil.fromHex("0539").get,
    attestationDataBytes: Option[ArrayBuffer] = None,
    extensionsCborBytes: Option[ArrayBuffer] = None
  ): ArrayBuffer =
    (Vector[Byte]()
      ++ sha256(rpId)
      ++ List((0x01b | (if (attestationDataBytes.isDefined) 0x40b else 0x00b) | (if (extensionsCborBytes.isDefined) 0x80b else 0x00b)).toByte)
      ++ (attestationDataBytes getOrElse Nil)
      ++ (extensionsCborBytes getOrElse Nil)
      )

  def makeAttestationDataBytes(
    rpId: String = DefaultRpId,
    credentialPublicKeyCose: ArrayBuffer = BinaryUtil.fromHex("a363616c67654553323536617858204eaf24df66dacb63303ac1ccf6f3c651b20e60f9fde0fe555fa9996f5074a495617958202988fefcb7b03299bb0b40126cf2618d8d9164c2be17fa76130b1ea083c1d1e6").get,
    counterBytes: ArrayBuffer = BinaryUtil.fromHex("0539").get,
    aaguid: ArrayBuffer = Vector[Byte](0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15)
  ): ArrayBuffer = {
    val credentialId = sha256(credentialPublicKeyCose)

    (Vector[Byte]()
      ++ aaguid
      ++ util.BinaryUtil.fromHex("0020").get
      ++ credentialId
      ++ credentialPublicKeyCose
    )
  }

  def generateEcKeypair(): KeyPair = {
    val factory = KeyFactory.getInstance("ECDSA", BcProvider)
    val ecSpec  = ECNamedCurveTable.getParameterSpec("P-256")
    val g: KeyPairGenerator = KeyPairGenerator.getInstance("ECDSA", "BC")
    g.initialize(ecSpec, new SecureRandom())

    g.generateKeyPair()
  }

  def generateAttestationCertificate(): (X509Certificate, PrivateKey) = {
    val name = new X500Name("CN=Yubico WebAuthn unit tests")
    val keypair: KeyPair = generateEcKeypair()

    (
      CertificateParser.parseDer(
        new X509v3CertificateBuilder(
          name,
          new BigInteger("1337"),
          Date.from(Instant.parse("2018-09-06T17:42:00Z")),
          Date.from(Instant.parse("2018-09-06T17:42:00Z")),
          name,
          SubjectPublicKeyInfo.getInstance(keypair.getPublic.getEncoded)
        )
        .build(new JcaContentSignerBuilder("SHA256withECDSA").build(keypair.getPrivate))
        .getEncoded
      ),
      keypair.getPrivate
    )
  }

}
