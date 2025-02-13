package com.yubico.webauthn.data

import com.yubico.webauthn.data.Extensions.CredentialProtection.CredentialProtectionPolicy

/** Internal re-exports of package-private members, for accessing them in tests
  */
object ReexportHelpers {

  def credProtectPolicyCborValue(policy: CredentialProtectionPolicy): Int =
    policy.cborValue

}
