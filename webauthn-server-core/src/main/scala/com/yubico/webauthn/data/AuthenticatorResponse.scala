package com.yubico.webauthn.data

import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.databind.JsonNode
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding

trait AuthenticatorResponse {

  val authenticatorData: ArrayBuffer

  @JsonProperty("authenticatorData")
  def authenticatorDataBase64: Base64UrlString = U2fB64Encoding.encode(authenticatorData.toArray)

  @JsonProperty("_authenticatorData")
  def parsedAuthenticatorData: AuthenticatorData = AuthenticatorData(authenticatorData)

  val clientDataJSON: ArrayBuffer

  /**
    * The [clientDataJSON] parsed as a [[JsonNode]].
    */
  @JsonProperty("_clientData")
  def clientData: JsonNode

  /**
    * The `clientData` parsed as a domain object.
    */
  @JsonIgnore
  lazy val collectedClientData: CollectedClientData = CollectedClientData(clientData)

  @JsonProperty("clientDataJSON")
  def clientDataJSONBase64: String = U2fB64Encoding.encode(clientDataJSON.toArray)

}
