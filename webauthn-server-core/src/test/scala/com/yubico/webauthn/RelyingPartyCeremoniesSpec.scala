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

import com.yubico.webauthn.data.PublicKeyCredentialDescriptor
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions
import com.yubico.webauthn.test.Helpers
import com.yubico.webauthn.test.RealExamples
import org.junit.runner.RunWith
import org.scalatest.FunSpec
import org.scalatest.Matchers
import org.scalatestplus.junit.JUnitRunner

import scala.jdk.CollectionConverters._

@RunWith(classOf[JUnitRunner])
class RelyingPartyCeremoniesSpec
    extends FunSpec
    with Matchers
    with TestWithEachProvider {

  private def newRp(
      testData: RealExamples.Example,
      credentialRepo: CredentialRepository,
  ): RelyingParty =
    RelyingParty
      .builder()
      .identity(testData.rp)
      .credentialRepository(credentialRepo)
      .build()

  private def createCheck(
      modRp: RelyingParty => RelyingParty = identity
  )(testData: RealExamples.Example): Unit = {
    val registrationRp =
      modRp(newRp(testData, Helpers.CredentialRepository.empty))

    val registrationRequest = registrationRp
      .startRegistration(
        StartRegistrationOptions.builder().user(testData.user).build()
      )
      .toBuilder
      .challenge(testData.attestation.challenge)
      .build()
    val registrationResult = registrationRp.finishRegistration(
      FinishRegistrationOptions
        .builder()
        .request(registrationRequest)
        .response(testData.attestation.credential)
        .build()
    );

    registrationResult.getKeyId.getId should equal(
      testData.attestation.credential.getId
    )
    registrationResult.isAttestationTrusted should be(false)
    registrationResult.getAttestationMetadata.isPresent should be(false)

    val assertionRp = newRp(
      testData,
      Helpers.CredentialRepository.withUser(
        testData.user,
        Helpers.toRegisteredCredential(testData.user, registrationResult),
      ),
    ).toBuilder
      .allowUnrequestedExtensions(true)
      .build()

    val assertionResult = assertionRp.finishAssertion(
      FinishAssertionOptions
        .builder()
        .request(
          AssertionRequest
            .builder()
            .publicKeyCredentialRequestOptions(
              PublicKeyCredentialRequestOptions
                .builder()
                .challenge(testData.assertion.challenge)
                .allowCredentials(
                  List(
                    PublicKeyCredentialDescriptor
                      .builder()
                      .id(testData.assertion.id)
                      .build()
                  ).asJava
                )
                .build()
            )
            .username(testData.user.getName)
            .build()
        )
        .response(testData.assertion.credential)
        .build()
    )

    assertionResult.isSuccess should be(true)
    assertionResult.getCredentialId should equal(testData.assertion.id)
    assertionResult.getUserHandle should equal(testData.user.getId)
    assertionResult.getUsername should equal(testData.user.getName)
    assertionResult.getSignatureCount should be >= testData.attestation.authenticatorData.getSignatureCounter
    assertionResult.isSignatureCounterValid should be(true)
  }

  testWithEachProvider { it =>
    describe("The default RelyingParty settings") {
      val check = createCheck()(_)

      describe("can register and then authenticate") {
        it("a YubiKey NEO.") {
          check(RealExamples.YubiKeyNeo)
        }
        it("a YubiKey 4.") {
          check(RealExamples.YubiKey4)
        }
        it("a YubiKey 5 NFC.") {
          check(RealExamples.YubiKey5)
        }
        it("an early YubiKey 5 NFC.") {
          check(RealExamples.YubiKey5Nfc)
        }
        it("a newer YubiKey 5 NFC.") {
          check(RealExamples.YubiKey5NfcPost5cNfc)
        }
        it("a YubiKey 5C NFC.") {
          check(RealExamples.YubiKey5cNfc)
        }
        it("a YubiKey 5 Nano.") {
          check(RealExamples.YubiKey5Nano)
        }
        it("a YubiKey 5Ci.") {
          check(RealExamples.YubiKey5Ci)
        }
        it("a Security Key by Yubico.") {
          check(RealExamples.SecurityKey)
        }
        it("a Security Key 2 by Yubico.") {
          check(RealExamples.SecurityKey2)
        }
        it("a Security Key NFC by Yubico.") {
          check(RealExamples.SecurityKeyNfc)
        }

        ignore("a YubiKey 5 NFC FIPS.") { // TODO Un-ignore when allowUnrequestedExtensions default changes to true
          check(RealExamples.YubikeyFips5Nfc)
        }

        it("a YubiKey 5Ci FIPS.") {
          check(RealExamples.Yubikey5ciFips)
        }
        it("a YubiKey Bio.") {
          check(RealExamples.YubikeyBio_5_5_4)
          check(RealExamples.YubikeyBio_5_5_5)
        }

        it("an Apple iOS device.") {
          check(RealExamples.AppleAttestationIos)
        }
        it("an Apple MacOS device.") {
          check(RealExamples.AppleAttestationMacos)
        }
      }
    }

    describe("The default RelyingParty settings, but with allowUnrequestedExtensions(true)") {

      describe("can register and then authenticate") {
        val check = createCheck(rp =>
          rp.toBuilder.allowUnrequestedExtensions(true).build()
        )(_)

        it("a YubiKey 5 NFC FIPS.") { // TODO Delete when allowUnrequestedExtensions default changes to true
          check(RealExamples.YubikeyFips5Nfc)
        }
      }
    }
  }
}
