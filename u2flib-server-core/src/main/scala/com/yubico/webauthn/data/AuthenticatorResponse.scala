package com.yubico.webauthn.data

import java.security.MessageDigest

import com.fasterxml.jackson.databind.JsonNode

trait AuthenticatorResponse {
  val clientDataJSON: ArrayBuffer

  /**
    * The [clientDataJSON] parsed as a [[JsonNode]].
    */
  def clientData: JsonNode

}
