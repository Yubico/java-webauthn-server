package com.yubico.webauthn.util

import java.security.PublicKey
import java.security.KeyFactory
import java.security.Provider
import java.security.interfaces.ECPublicKey

import com.fasterxml.jackson.core.Base64Variants
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.databind.node.JsonNodeFactory
import com.fasterxml.jackson.databind.node.ObjectNode
import com.fasterxml.jackson.dataformat.cbor.CBORFactory
import com.yubico.webauthn.data.ArrayBuffer
import com.yubico.webauthn.data.COSEAlgorithmIdentifier
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECParameterSpec
import org.bouncycastle.jce.spec.ECPublicKeySpec

import scala.collection.JavaConverters._


object WebAuthnCodecs {

  private val javaCryptoProvider: Provider = new BouncyCastleProvider
  private def jsonFactory = JsonNodeFactory.instance

  def cbor: ObjectMapper = new ObjectMapper(new CBORFactory()).setBase64Variant(Base64Variants.MODIFIED_FOR_URL)

  def json: ObjectMapper = new ObjectMapper().setBase64Variant(Base64Variants.MODIFIED_FOR_URL)

  def coseKeyToRaw(key: ObjectNode): ArrayBuffer = {
    assert(
      key.get("alg").isNumber && key.get("alg").longValue == javaAlgorithmNameToCoseAlgorithmIdentifier("ES256"),
      s"""COSE key must have the property "alg" set to ${javaAlgorithmNameToCoseAlgorithmIdentifier("ES256")}."""
    )
    assert(
      key.get("x").isBinary && key.get("y").isBinary(),
      """COSE key must have binary "x" and "y" properties."""
    )
    val xBytes = key.get("x").binaryValue()
    val yBytes = key.get("y").binaryValue()

    Vector[Byte](0x04) ++ (xBytes takeRight 32) ++ (yBytes takeRight 32)
  }

  def rawEcdaKeyToCose(key: ArrayBuffer): ObjectNode = {
    assert(
      key.length == 64
        || (key.length == 65 && key.head == 0x04),
      s"Raw key must be 64 bytes long or be 65 bytes long and start with 0x04, was ${key.length} bytes starting with ${key.head.formatted("%02x")}"
    )

    val start: Int = if (key.length == 64) 0 else 1

    jsonFactory.objectNode().setAll(Map(
      "alg" -> jsonFactory.numberNode(javaAlgorithmNameToCoseAlgorithmIdentifier("ES256")),
      "x" -> jsonFactory.binaryNode(key.slice(start, start + 32).toArray),
      "y" -> jsonFactory.binaryNode(key.drop(start + 32).toArray)
    ).asJava).asInstanceOf[ObjectNode]
  }

  def ecPublicKeyToCose(key: ECPublicKey): ObjectNode =
    jsonFactory.objectNode().setAll(Map(
      "alg" -> jsonFactory.numberNode(WebAuthnCodecs.javaAlgorithmNameToCoseAlgorithmIdentifier(key.getAlgorithm)),
      "x" -> jsonFactory.binaryNode(key.getW.getAffineX.toByteArray),
      "y" -> jsonFactory.binaryNode(key.getW.getAffineY.toByteArray)
    ).asJava).asInstanceOf[ObjectNode]

  def importCoseP256PublicKey(key: ObjectNode): PublicKey = {
    val ecSpec: ECParameterSpec = ECNamedCurveTable.getParameterSpec("secp256r1")

    val kf: KeyFactory = KeyFactory.getInstance("ECDSA", javaCryptoProvider)

    ecSpec.getCurve

    val pubKeySpec: ECPublicKeySpec = new ECPublicKeySpec(
      ecSpec.getCurve.decodePoint(coseKeyToRaw(key).toArray),
      ecSpec
    )

    kf.generatePublic(pubKeySpec)
  }

  def javaAlgorithmNameToCoseAlgorithmIdentifier(alg: String): COSEAlgorithmIdentifier = alg match {
    case "ECDSA" | "ES256" => -7
    case "RS256" => -257
  }

}
