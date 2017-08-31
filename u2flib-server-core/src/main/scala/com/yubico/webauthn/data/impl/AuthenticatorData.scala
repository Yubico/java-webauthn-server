package com.yubico.webauthn.data.impl

import java.nio.ByteBuffer

import com.yubico.webauthn.data.ArrayBuffer


case class AuthenticatorData(
  private val authData: ArrayBuffer,
) {

  /**
    * The SHA-256 hash of the RP ID associated with the credential.
    */
  val rpIdHash: ArrayBuffer = authData.slice(0, 32)

  /**
    * The flags byte.
    */
  val flags: AuthenticationDataFlags = AuthenticationDataFlags(authData(32))

  /**
    * The 32-bit unsigned signature counter.
    */
  val signatureCounter: Long =
    // Prepend zeroes so we can parse it as a signed int64 instead of a signed int32
    ByteBuffer.wrap((Vector[Byte](0, 0, 0, 0) ++ authData.slice(33, 37)).toArray).getLong

}
