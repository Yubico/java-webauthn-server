package com.yubico.webauthn.data.impl

import java.util.Optional

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonCreator
import com.yubico.scala.util.JavaConverters._
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding
import com.yubico.webauthn.data.ArrayBuffer

case class AuthenticatorAssertionResponse(
  override val clientDataJSON: ArrayBuffer,
  override val authenticatorData: ArrayBuffer,
  override val signature: ArrayBuffer,
  override val userHandle: Optional[ArrayBuffer]

) extends com.yubico.webauthn.data.AuthenticatorAssertionResponse
  with JacksonAuthenticatorResponse {

  @JsonCreator
  def this(
    @JsonProperty("authenticatorData") authenticatorDataBase64: String,
    @JsonProperty("clientDataJSON") clientDataJsonBase64: String,
    @JsonProperty("signature") signatureBase64: String,
    @JsonProperty("userHandle") userHandleBase64: String
  ) =
    this(
      authenticatorData = U2fB64Encoding.decode(authenticatorDataBase64).toVector,
      clientDataJSON = U2fB64Encoding.decode(clientDataJsonBase64).toVector,
      signature = U2fB64Encoding.decode(signatureBase64).toVector,
      userHandle = (Option(userHandleBase64) map { uh => U2fB64Encoding.decode(uh).toVector }).asJava
    )

}
