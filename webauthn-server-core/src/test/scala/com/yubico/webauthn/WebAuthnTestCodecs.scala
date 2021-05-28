package com.yubico.webauthn

import com.upokecenter.cbor.CBORObject
import com.yubico.webauthn.data.ByteArray
import com.yubico.webauthn.data.COSEAlgorithmIdentifier
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey

import java.security.KeyFactory
import java.security.PrivateKey
import java.security.PublicKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec

/** Re-exports from [[WebAuthnCodecs]] and [[Crypto]] so tests can use it
  */
object WebAuthnTestCodecs {

  def sha256(bytes: ByteArray): ByteArray = Crypto.sha256(bytes)

  def ecPublicKeyToRaw = WebAuthnCodecs.ecPublicKeyToRaw _
  def importCosePublicKey = WebAuthnCodecs.importCosePublicKey _

  def ecPublicKeyToCose(key: ECPublicKey): ByteArray =
    rawEcdaKeyToCose(ecPublicKeyToRaw(key))

  def rawEcdaKeyToCose(key: ByteArray): ByteArray = {
    val keyBytes = key.getBytes
    if (
      !(keyBytes.length == 64 || (keyBytes.length == 65 && keyBytes(0) == 0x04))
    ) {
      throw new IllegalArgumentException(
        s"Raw key must be 64 bytes long or be 65 bytes long and start with 0x04, was ${keyBytes.length} bytes starting with ${keyBytes(0)}"
      )
    }
    val start: Int =
      if (keyBytes.length == 64) 0
      else 1

    val coseKey: java.util.Map[Long, Any] = new java.util.HashMap[Long, Any]
    coseKey.put(1L, 2L) // Key type: EC

    coseKey.put(3L, COSEAlgorithmIdentifier.ES256.getId)
    coseKey.put(-1L, 1L) // Curve: P-256

    coseKey.put(
      -2L,
      java.util.Arrays.copyOfRange(keyBytes, start, start + 32),
    ) // x

    coseKey.put(
      -3L,
      java.util.Arrays.copyOfRange(keyBytes, start + 32, start + 64),
    ) // y

    new ByteArray(CBORObject.FromObject(coseKey).EncodeToBytes)
  }

  def publicKeyToCose(key: PublicKey): ByteArray = {
    key match {
      case k: ECPublicKey => ecPublicKeyToCose(k)
      case other =>
        throw new UnsupportedOperationException(
          "Unknown key type: " + other.getClass.getCanonicalName
        )
    }
  }

  def importPrivateKey(
      encodedKey: ByteArray,
      alg: COSEAlgorithmIdentifier,
  ): PrivateKey =
    alg match {
      case COSEAlgorithmIdentifier.ES256 =>
        val keyFactory: KeyFactory = KeyFactory.getInstance("EC")
        val spec = new PKCS8EncodedKeySpec(encodedKey.getBytes)
        keyFactory.generatePrivate(spec)

      case COSEAlgorithmIdentifier.EdDSA =>
        val keyFactory: KeyFactory = KeyFactory.getInstance("EdDSA")
        val spec = new PKCS8EncodedKeySpec(encodedKey.getBytes)
        keyFactory.generatePrivate(spec)

      case COSEAlgorithmIdentifier.RS256 | COSEAlgorithmIdentifier.RS1 =>
        val keyFactory: KeyFactory = KeyFactory.getInstance("RSA")
        val spec = new PKCS8EncodedKeySpec(encodedKey.getBytes)
        keyFactory.generatePrivate(spec)
    }

  def importEcdsaPrivateKey(encodedKey: ByteArray): PrivateKey = {
    val keyFactory: KeyFactory = KeyFactory.getInstance("EC")
    val spec = new PKCS8EncodedKeySpec(encodedKey.getBytes)
    keyFactory.generatePrivate(spec)
  }

  def eddsaPublicKeyToCose(key: BCEdDSAPublicKey): ByteArray = {
    val coseKey: java.util.Map[Long, Any] = new java.util.HashMap[Long, Any]
    coseKey.put(1L, 1L) // Key type: octet key pair

    coseKey.put(3L, COSEAlgorithmIdentifier.EdDSA.getId)
    coseKey.put(-1L, 6L) // crv: Ed25519

    coseKey.put(-2L, key.getEncoded.takeRight(32)) // Strip ASN.1 prefix
    new ByteArray(CBORObject.FromObject(coseKey).EncodeToBytes)
  }

  def rsaPublicKeyToCose(
      key: RSAPublicKey,
      alg: COSEAlgorithmIdentifier,
  ): ByteArray = {
    val coseKey: java.util.Map[Long, Any] = new java.util.HashMap[Long, Any]
    coseKey.put(1L, 3L) // Key type: RSA

    coseKey.put(3L, alg.getId)
    coseKey.put(-1L, key.getModulus.toByteArray) // public modulus n

    coseKey.put(-2L, key.getPublicExponent.toByteArray) // public exponent e

    new ByteArray(CBORObject.FromObject(coseKey).EncodeToBytes)
  }

  def getCoseAlgId(encodedPublicKey: ByteArray): COSEAlgorithmIdentifier = {
    importCosePublicKey(encodedPublicKey).getAlgorithm match {
      case "EC" => COSEAlgorithmIdentifier.ES256
      case other =>
        throw new UnsupportedOperationException("Unknown algorithm: " + other)
    }
  }

}
