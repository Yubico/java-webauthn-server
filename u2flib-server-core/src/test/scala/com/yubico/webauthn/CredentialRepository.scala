package com.yubico.webauthn

import java.security.PublicKey
import java.util.Optional

import com.yubico.webauthn.data.ArrayBuffer
import com.yubico.webauthn.data.Base64UrlString


trait CredentialRepository {

  def lookup(credentialId: ArrayBuffer): Optional[PublicKey]
  def lookup(credentialId: Base64UrlString): Optional[PublicKey]

}
