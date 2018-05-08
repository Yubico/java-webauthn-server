package com.yubico.webauthn.data

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.databind.JsonNode
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding
import com.yubico.webauthn.util.WebAuthnCodecs


case class AttestationObject(

  private val attestationObject: ArrayBuffer

) {

  private val decoded =
    WebAuthnCodecs.cbor.readTree(attestationObject.toArray)

  @JsonProperty
  def authenticatorData: AuthenticatorData = {
    val authData = decoded.get("authData")
    if (authData.isBinary)
      AuthenticatorData(authData.binaryValue.toVector)
    else
      AuthenticatorData(U2fB64Encoding.decode(authData.textValue).toVector)
  }

  @JsonProperty
  def attestationStatement: JsonNode = decoded.get("attStmt")

  /**
    * The ''attestation statement format'' of this attestation object.
    */
  @JsonProperty
  def format: String = decoded.get("fmt").asText

}
