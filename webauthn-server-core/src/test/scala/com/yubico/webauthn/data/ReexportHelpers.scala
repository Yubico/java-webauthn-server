package com.yubico.webauthn.data

import com.yubico.webauthn.data.Extensions.CredentialProperties.CredentialPropertiesOutput

/** Public re-exports of things in the com.yubico.webauthn.data package, so that
  * tests can access them but dependent projects cannot (unless they do this
  * same workaround hack).
  */
object ReexportHelpers {
  def newCredentialPropertiesOutput(rk: Boolean): CredentialPropertiesOutput =
    new CredentialPropertiesOutput(rk)
}
