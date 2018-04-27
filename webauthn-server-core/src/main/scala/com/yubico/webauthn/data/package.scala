package com.yubico.webauthn

import com.fasterxml.jackson.databind.JsonNode

package object data {

  /** An immutable array of bytes. */
  type ArrayBuffer = Vector[Byte]

  /** Container for extension values in [[PublicKeyCredential]]. */
  type AuthenticationExtensionsClientInputs = JsonNode

  /** A URL-safe base64 encoded array of bytes. */
  type Base64UrlString = String

  /** A hexadecimal-encoded array of bytes. */
  type HexString = String

  /**
    * A number identifying a cryptographic algorithm. The algorithm identifiers
    * SHOULD be values registered in the IANA COSE Algorithms registry, for
    * instance, -7 for "ES256" and -257 for "RS256".
    */
  type COSEAlgorithmIdentifier = Long

}
