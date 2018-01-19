package com.yubico.webauthn.data

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.databind.node.ObjectNode
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding

case class AttestationData private[data] (

  /**
    * The AAGUID of the authenticator.
    */
  @JsonIgnore
  aaguid: ArrayBuffer,

  /**
    * The ID of the attested credential.
    */
  @JsonIgnore
  credentialId: ArrayBuffer,

  /**
    * The ''credential public key'' encoded in COSE_Key format.
    *
    * @todo verify requirements https://www.w3.org/TR/webauthn/#sec-attestation-data
    */
  credentialPublicKey: ObjectNode

) {

  @JsonProperty("aaguid")
  def aaguidBase64: String = U2fB64Encoding.encode(aaguid.toArray)

  @JsonProperty("credentialId")
  def credentialIdBase64: String = U2fB64Encoding.encode(credentialId.toArray)

}
