package com.yubico.webauthn

import com.upokecenter.cbor.CBORObject
import com.yubico.webauthn.WebAuthnCodecs.rawEcKeyToCose
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
    rawEcKeyToCose(ecPublicKeyToRaw(key))

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

  def getCoseKty(encodedPublicKey: ByteArray): Int = {
    val cose = CBORObject.DecodeFromBytes(encodedPublicKey.getBytes)
    val kty = cose.get(CBORObject.FromObject(1)).AsInt32
    kty
  }

}
