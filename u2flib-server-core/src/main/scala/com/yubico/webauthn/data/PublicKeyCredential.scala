package com.yubico.webauthn.data

trait PublicKeyCredential[A <: AuthenticatorResponse] extends Credential {
  val rawId: ArrayBuffer
  val response: A
  val clientExtensionResults: AuthenticationExtensions
}
