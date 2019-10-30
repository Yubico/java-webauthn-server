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

package com.yubico.webauthn.attestation

import java.util.Collections
import java.util.Optional

import com.yubico.internal.util.scala.JavaConverters._
import com.yubico.internal.util.CertificateParser
import com.yubico.internal.util.JacksonCodecs
import com.yubico.webauthn.attestation.resolver.SimpleAttestationResolver
import com.yubico.webauthn.attestation.resolver.SimpleTrustResolver
import com.yubico.webauthn.test.RealExamples
import com.yubico.webauthn.CredentialRepository
import com.yubico.webauthn.RelyingParty
import com.yubico.webauthn.data.ByteArray
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor
import com.yubico.webauthn.FinishRegistrationOptions
import com.yubico.webauthn.RegisteredCredential
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions
import com.yubico.webauthn.data.PublicKeyCredentialParameters
import org.junit.runner.RunWith
import org.scalatest.FunSpec
import org.scalatest.Matchers
import org.scalatest.junit.JUnitRunner

import scala.collection.JavaConverters._


@RunWith(classOf[JUnitRunner])
class DeviceIdentificationSpec extends FunSpec with Matchers {

  def metadataService(metadataJson: String): StandardMetadataService = {
    val metadata = Collections.singleton(JacksonCodecs.json().readValue(metadataJson, classOf[MetadataObject]))
    new StandardMetadataService(
      new SimpleAttestationResolver(metadata, SimpleTrustResolver.fromMetadata(metadata))
    )
  }

  private val emptyCredentialRepository = new CredentialRepository {
    override def getCredentialIdsForUsername(username: String): java.util.Set[PublicKeyCredentialDescriptor] = Set.empty.asJava
    override def getUserHandleForUsername(username: String): Optional[ByteArray] = None.asJava
    override def getUsernameForUserHandle(userHandle: ByteArray): Optional[String] = None.asJava
    override def lookup(credentialId: ByteArray, userHandle: ByteArray): Optional[RegisteredCredential] = None.asJava
    override def lookupAll(credentialId: ByteArray): java.util.Set[RegisteredCredential] = Set.empty.asJava
  }

  describe("A RelyingParty with the default StandardMetadataService") {

    describe("correctly identifies") {
      def check(expectedName: String, testData: RealExamples.Example) {
        val rp = RelyingParty.builder()
          .identity(testData.rp)
          .credentialRepository(emptyCredentialRepository)
          .metadataService(new StandardMetadataService())
          .build()

        val result = rp.finishRegistration(FinishRegistrationOptions.builder()
          .request(PublicKeyCredentialCreationOptions.builder()
            .rp(testData.rp)
            .user(testData.user)
            .challenge(testData.attestation.challenge)
            .pubKeyCredParams(List(PublicKeyCredentialParameters.ES256).asJava)
            .build())
          .response(testData.attestation.credential)
          .build());

        result.isAttestationTrusted should be (true)
        result.getAttestationMetadata should not be empty
        result.getAttestationMetadata.get.getDeviceProperties should not be empty
        result.getAttestationMetadata.get.getDeviceProperties.get().get("displayName") should equal (expectedName)
      }

      it("a YubiKey NEO.") {
        check("YubiKey NEO/NEO-n", RealExamples.YubiKeyNeo)
      }
      it("a YubiKey 4.") {
        check("YubiKey 4/YubiKey 4 Nano", RealExamples.YubiKey4)
      }
      it("a YubiKey 5 NFC.") {
        check("YubiKey 5 NFC", RealExamples.YubiKey5)
      }
      it("a YubiKey 5 Nano.") {
        check("YubiKey 5 Series security key", RealExamples.YubiKey5Nano)
      }
      it("a Security Key by Yubico.") {
        check("Security Key by Yubico", RealExamples.SecurityKey)
      }
      it("a Security Key 2 by Yubico.") {
        check("Security Key by Yubico", RealExamples.SecurityKey2)
      }
      it("a Security Key NFC by Yubico.") {
        check("Security Key NFC by Yubico", RealExamples.SecurityKeyNfc)
      }
    }
  }

  describe("The default AttestationResolver") {
    describe("successfully identifies") {
      def check(expectedName: String, testData: RealExamples.Example) {
        val cert = CertificateParser.parseDer(testData.attestationCert.getBytes)
        val resolved = StandardMetadataService.createDefaultAttestationResolver().resolve(cert)
        resolved should not be empty
        resolved.get.getDeviceProperties should not be empty
        resolved.get.getDeviceProperties.get.get("displayName") should equal (expectedName)
      }

      it("a YubiKey NEO.") {
        check("YubiKey NEO/NEO-n", RealExamples.YubiKeyNeo)
      }
      it("a YubiKey 4.") {
        check("YubiKey 4/YubiKey 4 Nano", RealExamples.YubiKey4)
      }
      it("a YubiKey 5 NFC.") {
        check("YubiKey 5 NFC", RealExamples.YubiKey5)
      }
      it("a YubiKey 5 Nano.") {
        check("YubiKey 5 Series security key", RealExamples.YubiKey5Nano)
      }
      it("a Security Key by Yubico.") {
        check("Security Key by Yubico", RealExamples.SecurityKey)
      }
      it("a Security Key 2 by Yubico.") {
        check("Security Key by Yubico", RealExamples.SecurityKey2)
      }
      it("a Security Key NFC by Yubico.") {
        check("Security Key NFC by Yubico", RealExamples.SecurityKeyNfc)
      }
    }
  }

}
