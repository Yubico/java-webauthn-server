package com.yubico.webauthn.data

import java.security.PublicKey


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
