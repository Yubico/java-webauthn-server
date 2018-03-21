package com.yubico.webauthn.data

import java.util.Optional

import com.fasterxml.jackson.databind.JsonNode
import com.yubico.scala.util.JavaConverters._

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
    * The fully qualified origin of the requester, as identified by the client.
    */
  def origin: String = clientData.get("origin").asText

  /**
    * The URL-safe Base64 encoded TLS token binding ID the client has negotiated with the RP.
    */
  def tokenBinding: TokenBindingInfo = {
    val tb = clientData.get("tokenBinding")
    assert(tb != null, """Property "tokenBinding" missing from client data.""")
    assert(tb.isObject, """Property "tokenBinding" missing from client data.""")
    TokenBindingInfo(
      {
        val status = tb.get("status").textValue
        TokenBindingStatus.fromJson(status).getOrElse(
          throw new IllegalArgumentException("Invalid value for tokenBinding.status: " + status)
        )
      },
      Option(tb.get("id")).map(_.textValue)
    )
  }

  /**
    * The type of the requested operation, set by the client.
    */
  def `type`: String = clientData.get("type").asText

}
