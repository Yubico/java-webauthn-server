package com.yubico.webauthn.data

import com.fasterxml.jackson.annotation.JsonIgnore
import com.fasterxml.jackson.annotation.JsonProperty
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding


trait AuthenticatorAttestationResponse extends AuthenticatorResponse {

  @JsonIgnore
  val attestationObject: ArrayBuffer

  @JsonProperty("_attestationObject")
  lazy val attestation: AttestationObject = AttestationObject(attestationObject)

  @JsonProperty("attestationObject")
  def attestationObjectBase64: String = U2fB64Encoding.encode(attestationObject.toArray)

}
