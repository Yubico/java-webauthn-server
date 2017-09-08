package com.yubico.webauthn.data

trait AuthenticatorAttestationResponse extends AuthenticatorResponse {
  val attestationObject: ArrayBuffer

  lazy val attestation: AttestationObject = AttestationObject(attestationObject)

}
