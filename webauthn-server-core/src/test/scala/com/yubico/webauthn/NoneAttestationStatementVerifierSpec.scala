// Copyright (c) 2026, Yubico AB
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

package com.yubico.webauthn

import com.yubico.webauthn.TestAuthenticator.AttestationMaker
import org.junit.runner.RunWith
import org.scalatest.funspec.AnyFunSpec
import org.scalatest.matchers.should.Matchers
import org.scalatestplus.junit.JUnitRunner

import scala.util.Failure
import scala.util.Try

@RunWith(classOf[JUnitRunner])
class NoneAttestationStatementVerifierSpec
    extends AnyFunSpec
    with Matchers
    with TestWithEachProvider {

  val verifier = new NoneAttestationStatementVerifier

  testWithEachProvider { it =>
    describe("NoneAttestationStatementVerifier") {

      it("accepts an empty attStmt.") {
        val (credential, _, _) =
          TestAuthenticator.createBasicAttestedCredential(
            attestationMaker = AttestationMaker.none()
          )

        val result = verifier.verifyAttestationSignature(
          credential.getResponse.getAttestation,
          Crypto.sha256(credential.getResponse.getClientDataJSON),
        )

        result should be(true)
      }

      it("rejects an attStmt with properties.") {
        val (credential, _, _) =
          TestAuthenticator.createBasicAttestedCredential(
            attestationMaker = AttestationMaker.noneWithNonEmptyStatement()
          )

        val result = Try(
          verifier.verifyAttestationSignature(
            credential.getResponse.getAttestation,
            Crypto.sha256(credential.getResponse.getClientDataJSON),
          )
        )

        result shouldBe a[Failure[_]]
        result.failed.get shouldBe an[IllegalArgumentException]
      }
    }
  }
}
