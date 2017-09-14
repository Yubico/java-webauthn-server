package com.yubico.webauthn.util

import java.security.PublicKey
import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.KeyFactory
import java.security.Provider

import com.fasterxml.jackson.core.Base64Variants
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.dataformat.cbor.CBORFactory
import com.yubico.webauthn.data.ArrayBuffer
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECParameterSpec
import org.bouncycastle.jce.spec.ECPublicKeySpec


object WebAuthnCodecs {

  private val javaCryptoProvider: Provider = new BouncyCastleProvider

  def cbor: ObjectMapper = new ObjectMapper(new CBORFactory()).setBase64Variant(Base64Variants.MODIFIED_FOR_URL)

  def json: ObjectMapper = new ObjectMapper().setBase64Variant(Base64Variants.MODIFIED_FOR_URL)

  def coseKeyToRaw(key: JsonNode): ArrayBuffer = {
    assert(
      key.get("alg").isTextual && key.get("alg").textValue() == "ES256",
      """COSE key must have the property "alg" set to "ES256"."""
    )
    assert(
      key.get("x").isBinary && key.get("y").isBinary(),
      """COSE key must have binary "x" and "y" properties."""
    )
    val xBytes = key.get("x").binaryValue()
    val yBytes = key.get("y").binaryValue()

    Vector[Byte](0x04) ++ (xBytes takeRight 32) ++ (yBytes takeRight 32)
  }

  def coseKeyToRawArray(key: JsonNode): Array[Byte] = coseKeyToRaw(key).toArray

  def importCoseP256PublicKey(key: JsonNode): PublicKey = {
    val ecSpec: ECParameterSpec = ECNamedCurveTable.getParameterSpec("secp256r1")

    val kf: KeyFactory = KeyFactory.getInstance("ECDSA", javaCryptoProvider)

    ecSpec.getCurve

    val pubKeySpec: ECPublicKeySpec = new ECPublicKeySpec(
      ecSpec.getCurve.decodePoint(coseKeyToRawArray(key)),
      ecSpec
    )

    kf.generatePublic(pubKeySpec)
  }

}
