package com.yubico.webauthn.extension.uvm

import org.scalacheck.Gen

import scala.collection.immutable.ArraySeq

object Generators {

  def userVerificationMethod: Gen[UserVerificationMethod] =
    Gen.oneOf(ArraySeq.unsafeWrapArray(UserVerificationMethod.values))

  def keyProtectionType: Gen[KeyProtectionType] =
    Gen.oneOf(ArraySeq.unsafeWrapArray(KeyProtectionType.values))

  def matcherProtectionType: Gen[MatcherProtectionType] =
    Gen.oneOf(ArraySeq.unsafeWrapArray(MatcherProtectionType.values))

}
