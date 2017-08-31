package com.yubico.webauthn.data

import java.util.Optional

import com.fasterxml.jackson.databind.JsonNode

/**
  * High-level API for reading W3C specified values out of client data.
  *
  * @todo Implement client extensions and authenticator extensions.
  *
  * @param clientData the client data returned from, or to be sent to, the client.
  */
case class CollectedClientData(
  private val clientData: JsonNode
) {

  /**
    * The URL-safe Base64 encoded challenge as provided by the RP.
    */
  def challenge: Base64UrlString = clientData.get("challenge").asText

  /**
    * The fully qualified origin of the requester, as identified by the client.
    */
  def origin: String = clientData.get("origin").asText

  /**
    * The URL-safe Base64 encoded TLS token binding ID the client has negotiated with the RP.
    */
  def tokenBindingId: Optional[Base64UrlString] =
    Optional.ofNullable(clientData.get("tokenBindingId").asText)

}
