package com.yubico.webauthn

import java.security.PublicKey

import com.yubico.webauthn.data.ArrayBuffer


case class RegisteredCredential(
  credentialId: ArrayBuffer,
  publicKey: PublicKey,
  signatureCount: Long,
  userHandle: ArrayBuffer
)

