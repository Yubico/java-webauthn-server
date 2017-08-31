package com.yubico.webauthn.data.impl

import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.dataformat.cbor.CBORFactory
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding
import com.yubico.webauthn.data.ArrayBuffer


case class AttestationObject(

  private val attestationObject: ArrayBuffer,

) {

  private val decoded =
    new ObjectMapper(new CBORFactory()).readTree(attestationObject.toArray)

  def authenticatorData: AuthenticatorData =
    AuthenticatorData(Vector(U2fB64Encoding.decode(decoded.get("authData").asText) :_*))

  /**
    * The ''attestation statement format'' of this attestation object.
    */
  def format: String = decoded.get("fmt").asText

}
