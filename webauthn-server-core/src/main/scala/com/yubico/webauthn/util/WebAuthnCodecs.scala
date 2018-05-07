package com.yubico.webauthn.util

import java.security.interfaces.ECPublicKey

import com.fasterxml.jackson.core.Base64Variants
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.dataformat.cbor.CBORFactory
import com.upokecenter.cbor.CBORObject
import com.yubico.webauthn.data.ArrayBuffer
import com.yubico.webauthn.data.COSEAlgorithmIdentifier
import COSE.OneKey

import scala.collection.JavaConverters._


object WebAuthnCodecs {

  def cbor: ObjectMapper = new ObjectMapper(new CBORFactory()).setBase64Variant(Base64Variants.MODIFIED_FOR_URL)

  def json: ObjectMapper = new ObjectMapper().setBase64Variant(Base64Variants.MODIFIED_FOR_URL)

  def ecPublicKeyToRaw(key: ECPublicKey): ArrayBuffer = {
    val x = key.getW.getAffineX.toByteArray.toVector
    val y = key.getW.getAffineY.toByteArray.toVector

    Vector[Byte](0x04) ++ Vector.fill[Byte](32 - x.length)(0) ++ x.drop(x.length - 32) ++ Vector.fill[Byte](32 - y.length)(0) ++ y.drop(y.length - 32)
  }

  def rawEcdaKeyToCose(key: ArrayBuffer): ArrayBuffer = {
    assert(
      key.length == 64
        || (key.length == 65 && key.head == 0x04),
      s"Raw key must be 64 bytes long or be 65 bytes long and start with 0x04, was ${key.length} bytes starting with ${key.head.formatted("%02x")}"
    )

    val start: Int = if (key.length == 64) 0 else 1

    CBORObject.FromObject(Map(
      1 -> 2, // Key type: EC
      3 -> javaAlgorithmNameToCoseAlgorithmIdentifier("ES256"),
      -1 -> 1, // Curve: P-256
      -2 -> key.slice(start, start + 32).toArray, // x
      -3 -> key.drop(start + 32).toArray // y
    ).asJava)
      .EncodeToBytes
      .toVector
  }

  def ecPublicKeyToCose(key: ECPublicKey): ArrayBuffer = rawEcdaKeyToCose(ecPublicKeyToRaw(key))

  def importCoseP256PublicKey(key: Array[Byte]): ECPublicKey = importCoseP256PublicKey(key.toVector)
  def importCoseP256PublicKey(key: ArrayBuffer): ECPublicKey =
    new COSE.ECPublicKey(new OneKey(CBORObject.DecodeFromBytes(key.toArray)))

  def javaAlgorithmNameToCoseAlgorithmIdentifier(alg: String): COSEAlgorithmIdentifier = alg match {
    case "ECDSA" | "ES256" => -7
    case "RS256" => -257
  }

}
