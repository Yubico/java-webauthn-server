package com.yubico.webauthn

import java.util.Optional

import com.yubico.scala.util.JavaConverters._
import com.yubico.u2f.data.messages.key.util.U2fB64Encoding
import com.yubico.webauthn.data.ArrayBuffer
import com.yubico.webauthn.data.Base64UrlString


trait CredentialRepository {

  def lookup(credentialId: ArrayBuffer, userHandle: Optional[ArrayBuffer]): Optional[RegisteredCredential] =
    lookup(U2fB64Encoding.encode(credentialId.toArray), userHandle.asScala.map(uh => U2fB64Encoding.encode(uh.toArray)).asJava)

  def lookup(credentialId: Base64UrlString, userHandle: Optional[Base64UrlString]): Optional[RegisteredCredential]

}
