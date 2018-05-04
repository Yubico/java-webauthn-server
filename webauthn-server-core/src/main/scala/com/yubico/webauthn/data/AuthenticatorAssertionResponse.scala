package com.yubico.webauthn.data

import java.util.Optional

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonCreator
import com.yubico.scala.util.JavaConverters._
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding


case class AuthenticatorAssertionResponse(
  override val clientDataJSON: ArrayBuffer,
  override val authenticatorData: ArrayBuffer,
  signature: ArrayBuffer,
  userHandle: Optional[ArrayBuffer]

) extends AuthenticatorResponse {

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

  @JsonProperty("signature")
  def signatureBase64: Base64UrlString = U2fB64Encoding.encode(signature.toArray)
  @JsonProperty("userHandle")
  def userHandleBase64: Base64UrlString = (userHandle.asScala map { uh => U2fB64Encoding.encode(uh.toArray) }).orNull

}
