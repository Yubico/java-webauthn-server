package com.yubico.webauthn

package object data {

  /** An immutable array of bytes. */
  type ArrayBuffer = Vector[Byte]

  /** Container for extension values in [[PublicKeyCredential]]. */
  type AuthenticationExtensions = Map[String, Any]

}
