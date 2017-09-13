package com.yubico.webauthn.data.impl

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonCreator
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding
import com.yubico.webauthn.data.ArrayBuffer


case class AuthenticatorAttestationResponse (

  override val attestationObject: ArrayBuffer,
  override val clientDataJSON: ArrayBuffer

) extends com.yubico.webauthn.data.AuthenticatorAttestationResponse
  with JacksonAuthenticatorResponse {

  @JsonCreator
  def this(@JsonProperty("attestationObject") attestationObjectBase64: String, @JsonProperty("clientDataJSON") clientDataJsonBase64: String) =
    this(U2fB64Encoding.decode(attestationObjectBase64).toVector, U2fB64Encoding.decode(clientDataJsonBase64).toVector)

}
