package com.yubico.webauthn.data.impl

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonCreator
import com.fasterxml.jackson.annotation.JsonIgnoreProperties
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding
import com.yubico.webauthn.data.ArrayBuffer
import com.yubico.webauthn.data.AuthenticatorResponse
import com.yubico.webauthn.data.AuthenticationExtensionsClientInputs

@JsonIgnoreProperties(Array("rawId"))
case class PublicKeyCredential[+A <: AuthenticatorResponse] (

  override val rawId: ArrayBuffer,
  override val response: A,
  override val clientExtensionResults: AuthenticationExtensionsClientInputs

) extends com.yubico.webauthn.data.PublicKeyCredential[A] {

  @JsonCreator
  def this(
    @JsonProperty("id") idBase64: String,
    @JsonProperty response: A,
    @JsonProperty clientExtensionResults: AuthenticationExtensionsClientInputs
  ) =
    this(U2fB64Encoding.decode(idBase64).toVector, response, clientExtensionResults)

}
