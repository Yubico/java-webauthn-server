package com.yubico.webauthn.data.impl

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.JsonNode
import com.fasterxml.jackson.dataformat.cbor.CBORFactory
import com.yubico.webauthn.data.ArrayBuffer

case class AuthenticatorAttestationResponse (

  override val attestationObject: ArrayBuffer,
  override val clientDataJSON: ArrayBuffer,

) extends com.yubico.webauthn.data.AuthenticatorAttestationResponse
  with JacksonAuthenticatorResponse {

  lazy val attestation: JsonNode =
    new ObjectMapper(new CBORFactory()).readTree(attestationObject.toArray)

}
