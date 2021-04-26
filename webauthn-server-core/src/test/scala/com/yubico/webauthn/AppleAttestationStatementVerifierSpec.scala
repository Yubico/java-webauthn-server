// Copyright (c) 2021, Yubico AB
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

import com.yubico.internal.util.CertificateParser
import com.yubico.webauthn.TestAuthenticator.AttestationMaker
import com.yubico.webauthn.data.ByteArray
import com.yubico.webauthn.data.Generators.arbitraryByteArray
import com.yubico.webauthn.test.RealExamples
import org.junit.runner.RunWith
import org.scalatest.FunSpec
import org.scalatest.Matchers
import org.scalatestplus.junit.JUnitRunner
import org.scalatestplus.scalacheck.ScalaCheckDrivenPropertyChecks

@RunWith(classOf[JUnitRunner])
class AppleAttestationStatementVerifierSpec
    extends FunSpec
    with Matchers
    with TestWithEachProvider
    with ScalaCheckDrivenPropertyChecks {

  val verifier = new AppleAttestationStatementVerifier

  testWithEachProvider { it =>
    describe("AppleAttestationStatementVerifier") {

      describe("accepts") {
        describe("a real apple attestation statement example") {
          it("from iOS.") {
            val example = RealExamples.AppleAttestationIos
            val result = verifier.verifyAttestationSignature(
              example.attestation.attestationObject,
              example.attestation.clientDataJSONHash,
            )
            result should be(true)
          }

          it("from MacOS.") {
            val example = RealExamples.AppleAttestationMacos
            val result = verifier.verifyAttestationSignature(
              example.attestation.attestationObject,
              example.attestation.clientDataJSONHash,
            )
            result should be(true)
          }
        }

        it("a test-generated apple attestation statement.") {
          val (attestationMaker, _, _) = AttestationMaker.apple()
          val (pkc, _) = TestAuthenticator.createBasicAttestedCredential(
            attestationMaker = attestationMaker
          )
          val result = verifier.verifyAttestationSignature(
            pkc.getResponse.getAttestation,
            Crypto.sha256(pkc.getResponse.getClientDataJSON),
          )
          result should be(true)
        }
      }

      describe("rejects") {

        it("a real apple attestation statement example that doesn't match the clientDataJSONHash.") {
          val example = RealExamples.AppleAttestationIos
          verifier.verifyAttestationSignature(
            example.attestation.attestationObject,
            example.attestation.clientDataJSONHash,
          ) should be(true)

          forAll(
            com.yubico.webauthn.data.Generators
              .flipOneBit(example.attestation.clientDataJSONHash)
          ) { modifiedHash =>
            an[IllegalArgumentException] shouldBe thrownBy {
              verifier.verifyAttestationSignature(
                example.attestation.attestationObject,
                modifiedHash,
              )
            }
          }
        }

        it("an attestation statement without the attestation cert extension 1.2.840.113635.100.8.2 .") {
          val (attestationMaker, _, _) =
            AttestationMaker.apple(addNonceExtension = false)
          val (pkc, _) = TestAuthenticator.createBasicAttestedCredential(
            attestationMaker = attestationMaker
          )
          an[IllegalArgumentException] shouldBe thrownBy {
            verifier.verifyAttestationSignature(
              pkc.getResponse.getAttestation,
              Crypto.sha256(pkc.getResponse.getClientDataJSON),
            )
          }
        }

        it("an attestation statement where the 1.2.840.113635.100.8.2 extension value does not equal the nonceToHash.") {
          forAll { incorrectNonce: ByteArray =>
            val (attestationMaker, _, _) =
              AttestationMaker.apple(nonceValue = Some(incorrectNonce))
            val (pkc, _) = TestAuthenticator.createBasicAttestedCredential(
              attestationMaker = attestationMaker
            )

            an[IllegalArgumentException] shouldBe thrownBy {
              verifier.verifyAttestationSignature(
                pkc.getResponse.getAttestation,
                Crypto.sha256(pkc.getResponse.getClientDataJSON),
              )
            }
          }
        }

        it("an attestation statement where the certificate subject public key does not equal the credential public key.") {
          val certSubjectKeypair = TestAuthenticator.generateEcKeypair()
          val (appleAttestationMaker, caCert, _) =
            AttestationMaker.apple(certSubjectPublicKey =
              Some(certSubjectKeypair.getPublic)
            )
          val (pkc, _) = TestAuthenticator.createBasicAttestedCredential(
            attestationMaker = appleAttestationMaker
          )

          // In this test, the signature chain on its own is valid...
          val certNodes =
            pkc.getResponse.getAttestation.getAttestationStatement.get("x5c")
          var cert = CertificateParser.parseDer(certNodes.get(0).binaryValue)
          for { certIndex <- 1 until certNodes.size } {
            val nextCert =
              CertificateParser.parseDer(certNodes.get(certIndex).binaryValue)
            cert.verify(nextCert.getPublicKey)
            cert = nextCert
          }
          if (cert != caCert) {
            cert.verify(caCert.getPublicKey)
          }

          // ...but the leaf subject has the wrong public key.
          an[IllegalArgumentException] shouldBe thrownBy {
            verifier.verifyAttestationSignature(
              pkc.getResponse.getAttestation,
              Crypto.sha256(pkc.getResponse.getClientDataJSON),
            )
          }
        }
      }
    }

  }
}
