package com.yubico.webauthn.data

import java.security.interfaces.ECPublicKey

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonIgnore
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding
import com.yubico.webauthn.util.WebAuthnCodecs

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
  @JsonIgnore
  credentialPublicKey: ArrayBuffer

) {

  @JsonProperty("aaguid")
  def aaguidBase64: String = U2fB64Encoding.encode(aaguid.toArray)

  @JsonProperty("credentialId")
  def credentialIdBase64: String = U2fB64Encoding.encode(credentialId.toArray)

  @JsonProperty("credentialPublicKey")
  def credentialPublicKeyBase64: String = U2fB64Encoding.encode(credentialPublicKey.toArray)

  def parsedCredentialPublicKey: ECPublicKey = WebAuthnCodecs.importCoseP256PublicKey(credentialPublicKey)

}
