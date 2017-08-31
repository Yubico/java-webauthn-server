package com.yubico.webauthn.data

import java.util.Optional

import com.fasterxml.jackson.databind.JsonNode

trait AuthenticatorAttestationResponse extends AuthenticatorResponse {
  val attestationObject: ArrayBuffer

  /**
    * URL-safe Base64 encoded challenge provided by the RP.
    */
  def challenge: Base64UrlString

  /**
    * The [clientDataJSON] parsed as a [[JsonNode]].
    */
  def clientData: JsonNode

  /**
    * The fully qualified origin of the requester, as identified by the client
    */
  def origin: String

  /**
    * The URL-safe Base64 encoded TLS token binding ID the client has negotiated with the RP
    */
  def tokenBindingId: Optional[Base64UrlString]

}
