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

package com.yubico.webauthn

import com.yubico.webauthn.data.ByteArray
import com.yubico.webauthn.test.Util
import org.junit.runner.RunWith
import org.scalatest.FunSpec
import org.scalatest.Matchers
import org.scalatest.junit.JUnitRunner

import scala.util.Success
import scala.util.Try


@RunWith(classOf[JUnitRunner])
class PackedAttestationStatementVerifierSpec extends FunSpec with Matchers {

  val verifier = new PackedAttestationStatementVerifier

  describe("PackedAttestationStatementVerifier") {

    describe("verify the X.509 certificate requirements") {

      it("which pass Klas's attestation certificate.") {

        val cert = Util.importCertFromPem(getClass.getResourceAsStream("klas-cert.pem"))

        val result = Try(verifier.verifyX5cRequirements(cert, ByteArray.fromHex("F8A011F38C0A4D15800617111F9EDC7D")))

        result shouldBe a [Success[_]]
        result.get should be (true)
      }

    }

    describe("supports attestation certificates with the algorithm") {
      it ("ECDSA.") {
        val (cert, key) = TestAuthenticator.generateAttestationCertificate()
        val (credential, _) = TestAuthenticator.createBasicAttestedCredential(
          attestationCertAndKey = Some((cert, key)),
          attestationStatementFormat = "packed"
        )

        val result = verifier.verifyAttestationSignature(
          credential.getResponse.getAttestation,
          new BouncyCastleCrypto().hash(credential.getResponse.getClientDataJSON)
        )

        key.getAlgorithm should be ("ECDSA")
        result should be (true)
      }

      it ("RSA.") {
        val (cert, key) = TestAuthenticator.generateRsaCertificate()
        val (credential, _) = TestAuthenticator.createBasicAttestedCredential(
          attestationCertAndKey = Some((cert, key)),
          attestationStatementFormat = "packed"
        )

        val result = verifier.verifyAttestationSignature(
          credential.getResponse.getAttestation,
          new BouncyCastleCrypto().hash(credential.getResponse.getClientDataJSON)
        )

        key.getAlgorithm should be ("RSA")
        result should be (true)
      }
    }

  }

}
