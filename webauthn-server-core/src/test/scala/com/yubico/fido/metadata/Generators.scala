package com.yubico.fido.metadata

import org.scalacheck.Gen

object Generators {

  def userVerificationMethod: Gen[UserVerificationMethod] =
    Gen.oneOf(UserVerificationMethod.values)

  def keyProtectionType: Gen[KeyProtectionType] =
    Gen.oneOf(KeyProtectionType.values)

  def matcherProtectionType: Gen[MatcherProtectionType] =
    Gen.oneOf(MatcherProtectionType.values)

}
