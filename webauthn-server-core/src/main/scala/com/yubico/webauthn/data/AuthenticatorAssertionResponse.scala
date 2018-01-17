package com.yubico.webauthn.data

import java.util.Optional

import com.fasterxml.jackson.annotation.JsonProperty
import com.yubico.scala.util.JavaConverters._
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding


trait AuthenticatorAssertionResponse extends AuthenticatorResponse {

  val authenticatorData: ArrayBuffer
  val signature: ArrayBuffer
  val userHandle: Optional[ArrayBuffer]

  @JsonProperty("_authenticatorData")
  def parsedAuthenticatorData: AuthenticatorData = AuthenticatorData(authenticatorData)

  @JsonProperty("authenticatorData")
  def authenticatorDataBase64: String = U2fB64Encoding.encode(authenticatorData.toArray)
  @JsonProperty("signature")
  def signatureBase64: String = U2fB64Encoding.encode(signature.toArray)
  @JsonProperty("userHandle")
  def userHandleBase64: String = (userHandle.asScala map { uh => U2fB64Encoding.encode(uh.toArray) }).orNull

}
