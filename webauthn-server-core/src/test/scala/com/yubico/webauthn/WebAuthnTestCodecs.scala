package com.yubico.webauthn

import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPublicKey

import com.upokecenter.cbor.CBORObject
import com.yubico.webauthn.data.ByteArray
import com.yubico.webauthn.data.COSEAlgorithmIdentifier
import org.bouncycastle.jcajce.provider.asymmetric.edec.BCEdDSAPublicKey


/**
  * Re-exports from [[WebAuthnCodecs]] so tests can use it
  */
object WebAuthnTestCodecs {

  def ecPublicKeyToRaw = WebAuthnCodecs.ecPublicKeyToRaw _
  def importCosePublicKey = WebAuthnCodecs.importCosePublicKey _

  def ecPublicKeyToCose(key: ECPublicKey): ByteArray = rawEcdaKeyToCose(ecPublicKeyToRaw(key))

  def rawEcdaKeyToCose(key: ByteArray): ByteArray = {
    val keyBytes = key.getBytes
    if (!(keyBytes.length == 64 || (keyBytes.length == 65 && keyBytes(0) == 0x04))) {
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

    coseKey.put(-2L, java.util.Arrays.copyOfRange(keyBytes, start, start + 32)) // x

    coseKey.put(-3L, java.util.Arrays.copyOfRange(keyBytes, start + 32, start + 64)) // y

    new ByteArray(CBORObject.FromObject(coseKey).EncodeToBytes)
  }


  def eddsaPublicKeyToCose(key: BCEdDSAPublicKey): ByteArray = {
    val coseKey: java.util.Map[Long, Any] = new java.util.HashMap[Long, Any]
    coseKey.put(1L, 1L) // Key type: octet key pair

    coseKey.put(3L, COSEAlgorithmIdentifier.RS256.getId)
    coseKey.put(-1L, 6L) // crv: Ed25519

    coseKey.put(-2L, key.getEncoded)
    new ByteArray(CBORObject.FromObject(coseKey).EncodeToBytes)
  }

  def rsaPublicKeyToCose(key: RSAPublicKey): ByteArray = {
    val coseKey: java.util.Map[Long, Any] = new java.util.HashMap[Long, Any]
    coseKey.put(1L, 3L) // Key type: RSA

    coseKey.put(3L, COSEAlgorithmIdentifier.RS256.getId)
    coseKey.put(-1L, key.getModulus.toByteArray) // public modulus n

    coseKey.put(-2L, key.getPublicExponent.toByteArray) // public exponent e

    new ByteArray(CBORObject.FromObject(coseKey).EncodeToBytes)
  }

}
