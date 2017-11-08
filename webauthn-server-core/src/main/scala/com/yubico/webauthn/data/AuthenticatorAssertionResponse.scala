package com.yubico.webauthn.data

import com.fasterxml.jackson.annotation.JsonProperty
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding


trait AuthenticatorAssertionResponse extends AuthenticatorResponse {

  val authenticatorData: ArrayBuffer
  val signature: ArrayBuffer

  @JsonProperty("_authenticatorData")
  def parsedAuthenticatorData: AuthenticatorData = AuthenticatorData(authenticatorData)

  @JsonProperty("authenticatorData")
  def authenticatorDataBase64: String = U2fB64Encoding.encode(authenticatorData.toArray)
  @JsonProperty("signature")
  def signatureBase64: String = U2fB64Encoding.encode(signature.toArray)

}
