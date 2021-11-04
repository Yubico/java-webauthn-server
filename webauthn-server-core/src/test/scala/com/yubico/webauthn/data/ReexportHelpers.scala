package com.yubico.webauthn.data

import com.yubico.webauthn.data.Extensions.CredentialProperties.CredentialPropertiesOutput
import com.yubico.webauthn.data.Extensions.LargeBlob.LargeBlobAuthenticationOutput
import com.yubico.webauthn.data.Extensions.LargeBlob.LargeBlobRegistrationOutput

/** Public re-exports of things in the com.yubico.webauthn.data package, so that
  * tests can access them but dependent projects cannot (unless they do this
  * same workaround hack).
  */
object ReexportHelpers {

  def newCredentialPropertiesOutput(rk: Boolean): CredentialPropertiesOutput =
    new CredentialPropertiesOutput(rk)

  def newLargeBlobRegistrationOutput(
      supported: Boolean
  ): LargeBlobRegistrationOutput = new LargeBlobRegistrationOutput(supported)
  def newLargeBlobAuthenticationOutput(
      blob: Option[ByteArray],
      written: Option[Boolean],
  ): LargeBlobAuthenticationOutput =
    new LargeBlobAuthenticationOutput(
      blob.orNull,
      written.map(java.lang.Boolean.valueOf).orNull,
    )
}
