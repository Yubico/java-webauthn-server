package com.yubico.webauthn.data

import java.util.Optional

import com.fasterxml.jackson.annotation.JsonProperty
import com.yubico.scala.util.JavaConverters._
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding


trait AuthenticatorAssertionResponse extends AuthenticatorResponse {

  val signature: ArrayBuffer
  val userHandle: Optional[ArrayBuffer]

  @JsonProperty("signature")
  def signatureBase64: Base64UrlString = U2fB64Encoding.encode(signature.toArray)
  @JsonProperty("userHandle")
  def userHandleBase64: Base64UrlString = (userHandle.asScala map { uh => U2fB64Encoding.encode(uh.toArray) }).orNull

}
