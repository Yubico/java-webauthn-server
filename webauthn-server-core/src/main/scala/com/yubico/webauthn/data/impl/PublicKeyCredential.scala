package com.yubico.webauthn.data.impl

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonCreator
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding
import com.yubico.webauthn.data.ArrayBuffer
import com.yubico.webauthn.data.AuthenticatorResponse
import com.yubico.webauthn.data.AuthenticationExtensions

case class PublicKeyCredential[+A <: AuthenticatorResponse] (

  override val rawId: ArrayBuffer,
  override val response: A,
  override val clientExtensionResults: AuthenticationExtensions

) extends com.yubico.webauthn.data.PublicKeyCredential[A] {

  @JsonCreator
  def this(
    @JsonProperty("rawId") rawIdBase64: String,
    @JsonProperty response: A,
    @JsonProperty clientExtensionResults: AuthenticationExtensions
  ) =
    this(U2fB64Encoding.decode(rawIdBase64).toVector, response, clientExtensionResults)

}
