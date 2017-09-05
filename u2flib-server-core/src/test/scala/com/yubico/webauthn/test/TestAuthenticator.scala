package com.yubico.webauthn.test

import java.security.MessageDigest

import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.JsonNodeFactory
import com.yubico.webauthn.data
import com.yubico.webauthn.util
import com.yubico.webauthn.data.MakePublicKeyCredentialOptions
import com.yubico.webauthn.data.Base64UrlString
import com.yubico.webauthn.data.ArrayBuffer
import com.yubico.webauthn.util.WebAuthnCodecs
import com.yubico.webauthn.util.BinaryUtil

import scala.collection.JavaConverters._

object TestAuthenticator {

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


}
