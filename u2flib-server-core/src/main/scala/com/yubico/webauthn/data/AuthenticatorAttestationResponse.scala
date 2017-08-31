package com.yubico.webauthn.data

import com.fasterxml.jackson.databind.JsonNode

trait AuthenticatorAttestationResponse extends AuthenticatorResponse {
  val attestationObject: ArrayBuffer

  /**
    * The [clientDataJSON] parsed as a [[JsonNode]].
    */
  def clientData: JsonNode

  lazy val collectedClientData: CollectedClientData = CollectedClientData(clientData)

}
