package com.yubico.webauthn.data

import com.fasterxml.jackson.databind.JsonNode
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding
import com.yubico.webauthn.util.WebAuthnCodecs


case class AttestationObject(

  private val attestationObject: ArrayBuffer,

) {

  private val decoded =
    WebAuthnCodecs.cbor.readTree(attestationObject.toArray)

  def authenticatorData: AuthenticatorData =
    AuthenticatorData(U2fB64Encoding.decode(decoded.get("authData").asText).toVector)

  def attestationStatement: JsonNode = decoded.get("attStmt")

  /**
    * The ''attestation statement format'' of this attestation object.
    */
  def format: String = decoded.get("fmt").asText

}
