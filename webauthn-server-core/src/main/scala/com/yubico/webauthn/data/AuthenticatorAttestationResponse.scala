package com.yubico.webauthn.data

import com.fasterxml.jackson.annotation.JsonProperty
import com.fasterxml.jackson.annotation.JsonCreator
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding


case class AuthenticatorAttestationResponse (

  attestationObject: ArrayBuffer,
  override val clientDataJSON: ArrayBuffer

) extends AuthenticatorResponse {

  override lazy val authenticatorData: ArrayBuffer = attestation.authenticatorData.authData

  @JsonCreator
  def this(@JsonProperty("attestationObject") attestationObjectBase64: String, @JsonProperty("clientDataJSON") clientDataJsonBase64: String) =
    this(U2fB64Encoding.decode(attestationObjectBase64).toVector, U2fB64Encoding.decode(clientDataJsonBase64).toVector)

  @JsonProperty("_attestationObject")
  lazy val attestation: AttestationObject = AttestationObject(attestationObject)

  @JsonProperty("attestationObject")
  def attestationObjectBase64: String = U2fB64Encoding.encode(attestationObject.toArray)

}
