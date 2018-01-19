package com.yubico.webauthn

import java.security.PublicKey

import com.yubico.webauthn.data.ArrayBuffer


case class RegisteredCredential(
  credentialId: ArrayBuffer,
  publicKey: PublicKey,
  signatureCount: Long,
  userHandle: ArrayBuffer
) {
  def this(
    credentialId: ArrayBuffer,
    publicKey: PublicKey,
    signatureCount: Long,
    userHandle: Array[Byte]
  ) = this(credentialId, publicKey, signatureCount, userHandle.toVector)
}

