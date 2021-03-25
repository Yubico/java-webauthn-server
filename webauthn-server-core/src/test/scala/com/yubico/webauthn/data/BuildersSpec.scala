// Copyright (c) 2018, Yubico AB
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package com.yubico.webauthn.data

import com.fasterxml.jackson.core.`type`.TypeReference
import com.yubico.webauthn.AssertionRequest
import com.yubico.webauthn.AssertionResult
import com.yubico.webauthn.Generators._
import com.yubico.webauthn.RegistrationResult
import com.yubico.webauthn.attestation.Attestation
import com.yubico.webauthn.attestation.Generators._
import com.yubico.webauthn.data.Generators._
import org.junit.runner.RunWith
import org.scalacheck.Arbitrary
import org.scalatest.FunSpec
import org.scalatest.Matchers
import org.scalatestplus.junit.JUnitRunner
import org.scalatestplus.scalacheck.ScalaCheckDrivenPropertyChecks

import scala.language.reflectiveCalls

@RunWith(classOf[JUnitRunner])
class BuildersSpec
    extends FunSpec
    with Matchers
    with ScalaCheckDrivenPropertyChecks {

  type ToBuilder[A] = { def toBuilder(): { def build(): A } }

  describe("The class") {

    def test[A <: ToBuilder[A]](tpe: TypeReference[A])(implicit
        a: Arbitrary[A]
    ): Unit = {
      val cn = tpe.getType.getTypeName
      describe(s"${cn}") {
        it("has a working .toBuilder() method.") {
          forAll { value: A =>
            val rebuilt = value.toBuilder().build()
            rebuilt should equal(value)
          }
        }
      }
    }

    test(new TypeReference[AssertionExtensionInputs]() {})
    test(new TypeReference[AssertionRequest]() {})
    test(new TypeReference[AssertionResult]() {})
    test(new TypeReference[Attestation]() {})
    test(new TypeReference[AttestedCredentialData]() {})
    test(new TypeReference[AuthenticatorAssertionResponse]() {})
    test(new TypeReference[AuthenticatorAttestationResponse]() {})
    test(new TypeReference[AuthenticatorSelectionCriteria]() {})
    test(new TypeReference[ClientAssertionExtensionOutputs]() {})
    test(new TypeReference[ClientRegistrationExtensionOutputs]() {})
    test(
      new TypeReference[PublicKeyCredential[
        AuthenticatorAssertionResponse,
        ClientAssertionExtensionOutputs,
      ]]() {}
    )
    test(
      new TypeReference[PublicKeyCredential[
        AuthenticatorAttestationResponse,
        ClientRegistrationExtensionOutputs,
      ]]() {}
    )
    test(new TypeReference[PublicKeyCredentialCreationOptions]() {})
    test(new TypeReference[PublicKeyCredentialDescriptor]() {})
    test(new TypeReference[PublicKeyCredentialParameters]() {})
    test(new TypeReference[PublicKeyCredentialRequestOptions]() {})
    test(new TypeReference[RegistrationExtensionInputs]() {})
    test(new TypeReference[RegistrationResult]() {})
    test(new TypeReference[RelyingPartyIdentity]() {})
    test(new TypeReference[UserIdentity]() {})
  }

}
