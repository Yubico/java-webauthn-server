package com.yubico.webauthn.data

import com.fasterxml.jackson.annotation.JsonSubTypes
import com.fasterxml.jackson.annotation.JsonTypeInfo
import com.fasterxml.jackson.annotation.JsonSubTypes.Type
import com.fasterxml.jackson.annotation.JsonTypeInfo.Id
import com.fasterxml.jackson.databind.JsonNode

@JsonTypeInfo(use = Id.CLASS, include = JsonTypeInfo.As.PROPERTY, property = "@jackson_type")
@JsonSubTypes(Array(
  new Type(classOf[impl.AuthenticatorAssertionResponse]),
  new Type(classOf[impl.AuthenticatorAttestationResponse])
))
trait AuthenticatorResponse {
  val clientDataJSON: ArrayBuffer

  /**
    * The [clientDataJSON] parsed as a [[JsonNode]].
    */
  def clientData: JsonNode

  /**
    * The `clientData` parsed as a domain object.
    */
  lazy val collectedClientData: CollectedClientData = CollectedClientData(clientData)

}
