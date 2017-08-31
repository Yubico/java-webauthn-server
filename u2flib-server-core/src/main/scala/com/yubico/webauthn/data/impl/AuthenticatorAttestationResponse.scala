package com.yubico.webauthn.data.impl

import java.io.ByteArrayInputStream

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.JsonNode
import com.yubico.webauthn.data.ArrayBuffer

case class AuthenticatorAttestationResponse (

  override val attestationObject: ArrayBuffer,
  override val clientDataJSON: ArrayBuffer,

) extends com.yubico.webauthn.data.AuthenticatorAttestationResponse {

  override lazy val clientData: JsonNode =
    new ObjectMapper().readTree(new ByteArrayInputStream(clientDataJSON.toArray))

}
