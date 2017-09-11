package com.yubico.webauthn.data

trait AuthenticatorAssertionResponse extends AuthenticatorResponse {
  val authenticatorData: ArrayBuffer
  val signature: ArrayBuffer

  def parsedAuthenticatorData: AuthenticatorData = AuthenticatorData(authenticatorData)
}
