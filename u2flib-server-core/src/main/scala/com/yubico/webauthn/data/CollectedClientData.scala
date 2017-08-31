package com.yubico.webauthn.data

import java.util.Optional

import com.fasterxml.jackson.databind.JsonNode

/**
  * High-level API for reading W3C specified values out of client data.
  *
  * @param clientData the client data returned from, or to be sent to, the client.
  */
case class CollectedClientData(
  private val clientData: JsonNode
) {

  /**
    * Input or output values for or from authenticator extensions, if any.
    */
  def authenticatorExtensions: Optional[AuthenticationExtensions] = Optional.ofNullable(clientData.get("authenticatorExtensions"))

  /**
    * The URL-safe Base64 encoded challenge as provided by the RP.
    */
  def challenge: Base64UrlString = clientData.get("challenge").asText

  /**
    * Input or output values for or from client extensions, if any.
    */
  def clientExtensions: Optional[AuthenticationExtensions] = Optional.ofNullable(clientData.get("clientExtensions"))

  /**
    * The name of the algorithm the client used to compute the hash of the serialized client data.
    *
    * This SHOULD be a ''recognized algorithm name'', but [[CollectedClientData]] does not inforce it.
    */
  def hashAlgorithm: String = clientData.get("hashAlgorithm").asText

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
