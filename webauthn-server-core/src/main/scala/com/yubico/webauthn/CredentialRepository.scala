package com.yubico.webauthn

import java.util.Optional

import com.yubico.u2f.data.messages.key.util.U2fB64Encoding
import com.yubico.webauthn.data.ArrayBuffer
import com.yubico.webauthn.data.Base64UrlString


trait CredentialRepository {

  def lookup(credentialId: ArrayBuffer, userHandle: Option[ArrayBuffer]): Optional[RegisteredCredential] =
    lookup(U2fB64Encoding.encode(credentialId.toArray), userHandle map { uh => U2fB64Encoding.encode(uh.toArray) })

  def lookup(credentialId: Base64UrlString, userHandle: Option[Base64UrlString]): Optional[RegisteredCredential]

}
