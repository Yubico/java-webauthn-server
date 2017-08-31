package com.yubico.webauthn

import com.fasterxml.jackson.databind.JsonNode

package object data {

  /** An immutable array of bytes. */
  type ArrayBuffer = Vector[Byte]

  /** Container for extension values in [[PublicKeyCredential]]. */
  type AuthenticationExtensions = JsonNode

  /** A URL-safe base64 encoded array of bytes. */
  type Base64UrlString = String

}
