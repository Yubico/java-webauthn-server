package com.yubico.webauthn.data

trait PublicKeyCredential extends Credential {
  val rawId: ArrayBuffer
  val response: AuthenticatorResponse
  val clientExtensionResults: AuthenticationExtensions
}
