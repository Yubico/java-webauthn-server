package com.yubico.webauthn

import java.util.Optional

import com.yubico.webauthn.data.Base64UrlString
import com.yubico.webauthn.data.RegisteredCredential
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor


trait CredentialRepository {

  def getCredentialIdsForUsername(username: String): java.util.List[PublicKeyCredentialDescriptor]
  def lookup(credentialId: Base64UrlString, userHandle: Base64UrlString): Optional[RegisteredCredential]
  def lookupAll(credentialId: Base64UrlString): Set[RegisteredCredential]

}
