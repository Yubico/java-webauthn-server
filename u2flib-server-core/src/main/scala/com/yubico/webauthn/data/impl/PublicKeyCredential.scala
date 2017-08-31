package com.yubico.webauthn.data.impl

import com.yubico.webauthn.data.ArrayBuffer
import com.yubico.webauthn.data.AuthenticatorResponse
import com.yubico.webauthn.data.AuthenticationExtensions

case class PublicKeyCredential(

  override val id: String,
  override val rawId: ArrayBuffer,
  override val response: AuthenticatorResponse,
  override val clientExtensionResults: AuthenticationExtensions,

) extends com.yubico.webauthn.data.PublicKeyCredential {

  override val `type` = "public-key"

}
