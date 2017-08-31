package com.yubico.webauthn.data

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

}
