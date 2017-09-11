package com.yubico.webauthn

import java.security.PublicKey
import java.util.Optional

import com.yubico.u2f.data.messages.key.util.U2fB64Encoding
import com.yubico.webauthn.data.ArrayBuffer
import com.yubico.webauthn.data.Base64UrlString


trait CredentialRepository {

  def lookup(credentialId: ArrayBuffer): Optional[PublicKey] = lookup(U2fB64Encoding.encode(credentialId.toArray))
  def lookup(credentialId: Base64UrlString): Optional[PublicKey]

}
