package com.yubico.webauthn.data

import com.fasterxml.jackson.databind.JsonNode

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
