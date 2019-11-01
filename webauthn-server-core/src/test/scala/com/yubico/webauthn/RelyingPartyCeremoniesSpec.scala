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

import java.util.Optional

import com.yubico.internal.util.scala.JavaConverters._
import com.yubico.webauthn.data.ByteArray
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor
import com.yubico.webauthn.data.PublicKeyCredentialParameters
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions
import com.yubico.webauthn.test.RealExamples
import org.junit.runner.RunWith
import org.scalatest.FunSpec
import org.scalatest.Matchers
import org.scalatest.junit.JUnitRunner

import scala.collection.JavaConverters._


@RunWith(classOf[JUnitRunner])
class RelyingPartyCeremoniesSpec extends FunSpec with Matchers {

  private def newRp(testData: RealExamples.Example, credentialRepo: CredentialRepository): RelyingParty =
    RelyingParty.builder()
      .identity(testData.rp)
      .credentialRepository(credentialRepo)
      .build()

  private val emptyCredentialRepository = new CredentialRepository {
    override def getCredentialIdsForUsername(username: String): java.util.Set[PublicKeyCredentialDescriptor] = Set.empty.asJava
    override def getUserHandleForUsername(username: String): Optional[ByteArray] = None.asJava
    override def getUsernameForUserHandle(userHandle: ByteArray): Optional[String] = None.asJava
    override def lookup(credentialId: ByteArray, userHandle: ByteArray): Optional[RegisteredCredential] = None.asJava
    override def lookupAll(credentialId: ByteArray): java.util.Set[RegisteredCredential] = Set.empty.asJava
  }

  private def credentialRepoWithUser(testData: RealExamples.Example, reg: RegistrationResult): CredentialRepository = new CredentialRepository {
    override def getCredentialIdsForUsername(username: String): java.util.Set[PublicKeyCredentialDescriptor] =
      if (username == testData.user.getName)
        Set(PublicKeyCredentialDescriptor.builder().id(reg.getKeyId.getId).build()).asJava
      else Set.empty.asJava
    override def getUserHandleForUsername(username: String): Optional[ByteArray] =
      if (username == testData.user.getName)
        Some(testData.user.getId).asJava
      else None.asJava
    override def getUsernameForUserHandle(userHandle: ByteArray): Optional[String] =
      if (userHandle == testData.user.getId)
        Some(testData.user.getName).asJava
      else None.asJava
    override def lookup(credentialId: ByteArray, userHandle: ByteArray): Optional[RegisteredCredential] =
      if (credentialId == reg.getKeyId.getId && userHandle == testData.user.getId)
        Some(RegisteredCredential.builder()
          .credentialId(reg.getKeyId.getId)
          .userHandle(testData.user.getId)
          .publicKeyCose(reg.getPublicKeyCose)
          .build()).asJava
      else None.asJava
    override def lookupAll(credentialId: ByteArray): java.util.Set[RegisteredCredential] =
      if (credentialId == reg.getKeyId.getId)
        Set(lookup(credentialId, testData.user.getId).get()).asJava
      else Set.empty.asJava
  }

  describe("The default RelyingParty settings") {

    describe("can register and then authenticate") {
      def check(testData: RealExamples.Example) {
        val registrationRp = newRp(testData, emptyCredentialRepository)

        val registrationResult = registrationRp.finishRegistration(FinishRegistrationOptions.builder()
          .request(PublicKeyCredentialCreationOptions.builder()
            .rp(testData.rp)
            .user(testData.user)
            .challenge(testData.attestation.challenge)
            .pubKeyCredParams(List(PublicKeyCredentialParameters.ES256).asJava)
            .build())
          .response(testData.attestation.credential)
          .build());

        registrationResult.getKeyId.getId should equal (testData.attestation.credential.getId)
        registrationResult.isAttestationTrusted should be (false)
        registrationResult.getAttestationMetadata.isPresent should be (false)

        val assertionRp = newRp(testData, credentialRepoWithUser(testData, registrationResult))

        val assertionResult = assertionRp.finishAssertion(FinishAssertionOptions.builder()
          .request(AssertionRequest.builder()
            .publicKeyCredentialRequestOptions(PublicKeyCredentialRequestOptions.builder()
              .challenge(testData.assertion.challenge)
              .allowCredentials(List(PublicKeyCredentialDescriptor.builder().id(testData.assertion.id).build()).asJava)
              .build())
            .username(testData.user.getName)
            .build())
          .response(testData.assertion.credential)
          .build())

        assertionResult.isSuccess should be (true)
        assertionResult.getCredentialId should equal (testData.assertion.id)
        assertionResult.getUserHandle should equal (testData.user.getId)
        assertionResult.getUsername should equal (testData.user.getName)
        assertionResult.getSignatureCount should be >= testData.attestation.authenticatorData.getSignatureCounter
        assertionResult.isSignatureCounterValid should be (true)
      }

      it("a YubiKey NEO.") {
        check(RealExamples.YubiKeyNeo)
      }
      it("a YubiKey 4.") {
        check(RealExamples.YubiKey4)
      }
      it("a YubiKey 5 NFC.") {
        check(RealExamples.YubiKey5)
      }
      it("a YubiKey 5 Nano.") {
        check(RealExamples.YubiKey5Nano)
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
    }
  }
}
