package com.yubico.webauthn.data.impl

import com.fasterxml.jackson.databind.JsonNode
import com.yubico.webauthn.data.ArrayBuffer
import com.yubico.webauthn.util.WebAuthnCodecs


case class AuthenticatorAttestationResponse (

  override val attestationObject: ArrayBuffer,
  override val clientDataJSON: ArrayBuffer,

) extends com.yubico.webauthn.data.AuthenticatorAttestationResponse
  with JacksonAuthenticatorResponse {

  lazy val attestation: JsonNode =
    WebAuthnCodecs.cbor.readTree(attestationObject.toArray)

}
