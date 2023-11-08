package com.yubico.webauthn.data

import com.yubico.webauthn.data.Extensions.LargeBlob.LargeBlobAuthenticationOutput

/** Public re-exports of things in the com.yubico.webauthn.data package, so that
  * tests can access them but dependent projects cannot (unless they do this
  * same workaround hack).
  */
object ReexportHelpers {

  def newLargeBlobAuthenticationOutput(
      blob: Option[ByteArray],
      written: Option[Boolean],
  ): LargeBlobAuthenticationOutput =
    new LargeBlobAuthenticationOutput(
      blob.orNull,
      written.map(java.lang.Boolean.valueOf).orNull,
    )
}
