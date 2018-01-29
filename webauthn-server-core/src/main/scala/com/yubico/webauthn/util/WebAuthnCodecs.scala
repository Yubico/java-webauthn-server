package com.yubico.webauthn.util

import java.security.PublicKey
import java.security.KeyFactory
import java.security.Provider
import java.security.interfaces.ECPublicKey

import com.fasterxml.jackson.core.Base64Variants
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.node.JsonNodeFactory
import com.fasterxml.jackson.databind.node.ObjectNode
import com.fasterxml.jackson.dataformat.cbor.CBORFactory
import com.upokecenter.cbor.CBORObject
import com.yubico.webauthn.data.ArrayBuffer
import com.yubico.webauthn.data.COSEAlgorithmIdentifier
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECParameterSpec
import org.bouncycastle.jce.spec.ECPublicKeySpec
import COSE.OneKey

import scala.collection.JavaConverters._


object WebAuthnCodecs {

  private val javaCryptoProvider: Provider = new BouncyCastleProvider
  private def jsonFactory = JsonNodeFactory.instance

  def cbor: ObjectMapper = new ObjectMapper(new CBORFactory()).setBase64Variant(Base64Variants.MODIFIED_FOR_URL)

  def json: ObjectMapper = new ObjectMapper().setBase64Variant(Base64Variants.MODIFIED_FOR_URL)

  def ecPublicKeyToRaw(key: ECPublicKey): ArrayBuffer = {
    val x = key.getW.getAffineX.toByteArray.toVector
    val y = key.getW.getAffineX.toByteArray.toVector

    Vector[Byte](0x04) ++ Vector.fill[Byte](32 - x.length)(0) ++ x ++ Vector.fill[Byte](32 - x.length)(0) ++ y
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

  def importCoseP256PublicKey(key: Array[Byte]): ECPublicKey = importCoseP256PublicKey(key.toVector)
  def importCoseP256PublicKey(key: ArrayBuffer): ECPublicKey = {
    val cbor = CBORObject.DecodeFromBytes(key.toArray)
    val pubKey = new COSE.ECPublicKey(new OneKey(CBORObject.DecodeFromBytes(key.toArray)))
    pubKey
  }

  def javaAlgorithmNameToCoseAlgorithmIdentifier(alg: String): COSEAlgorithmIdentifier = alg match {
    case "ECDSA" | "ES256" => -7
    case "RS256" => -257
  }

}
