package com.yubico.webauthn.data.impl

import com.yubico.webauthn.data.ArrayBuffer

case class AuthenticatorAssertionResponse(

  override val clientDataJSON: ArrayBuffer,
  override val authenticatorData: ArrayBuffer,
  override val signature: ArrayBuffer,

) extends com.yubico.webauthn.data.AuthenticatorAssertionResponse
