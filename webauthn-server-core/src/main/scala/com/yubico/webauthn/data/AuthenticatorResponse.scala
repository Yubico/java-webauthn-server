package com.yubico.webauthn.data

import com.fasterxml.jackson.annotation.JsonSubTypes
import com.fasterxml.jackson.annotation.JsonTypeInfo
import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonSubTypes.Type
import com.fasterxml.jackson.annotation.JsonTypeInfo.Id
import com.fasterxml.jackson.databind.JsonNode
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding

@JsonTypeInfo(use = Id.CLASS, include = JsonTypeInfo.As.PROPERTY, property = "@jackson_type")
@JsonSubTypes(Array(
  new Type(classOf[impl.AuthenticatorAssertionResponse]),
  new Type(classOf[impl.AuthenticatorAttestationResponse])
))
trait AuthenticatorResponse {

  @JsonIgnore
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
