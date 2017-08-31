package com.yubico.webauthn.data.impl

import com.yubico.webauthn.data.ArrayBuffer
import com.yubico.webauthn.util.BinaryUtil


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
  val signatureCounter: Long = {
    val bytes = authData.slice(33, 37)
    BinaryUtil.getUint32(bytes) getOrElse {
      throw new IllegalArgumentException(s"Invalid signature counter bytes: ${bytes}")
    }
  }

}
