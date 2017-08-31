package com.yubico.webauthn.data.impl

import com.yubico.webauthn.data.ArrayBuffer

case class AuthenticatorAttestationResponse (

  override val attestationObject: ArrayBuffer,
  override val clientDataJSON: ArrayBuffer,

) extends com.yubico.webauthn.data.AuthenticatorAttestationResponse
