package com.yubico.webauthn

import java.util.Optional

import com.yubico.scala.util.JavaConverters._
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding
import com.yubico.webauthn.data.ArrayBuffer
import com.yubico.webauthn.data.Base64UrlString


trait CredentialRepository {

  def lookup(credentialId: Base64UrlString, userHandle: Optional[Base64UrlString]): Optional[RegisteredCredential]

}
