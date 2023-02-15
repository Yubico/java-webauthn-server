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

package com.yubico.fido.metadata

import com.fasterxml.jackson.core.`type`.TypeReference
import com.fasterxml.jackson.databind.ObjectMapper
import com.yubico.fido.metadata.Generators._
import org.junit.runner.RunWith
import org.scalacheck.Arbitrary
import org.scalatest.funspec.AnyFunSpec
import org.scalatest.matchers.should.Matchers
import org.scalatestplus.junit.JUnitRunner
import org.scalatestplus.scalacheck.ScalaCheckDrivenPropertyChecks

@RunWith(classOf[JUnitRunner])
class JsonIoSpec
    extends AnyFunSpec
    with Matchers
    with ScalaCheckDrivenPropertyChecks {

  def json: ObjectMapper = JacksonCodecs.jsonWithDefaultEnums()

  describe("The class") {

    def test[A](tpe: TypeReference[A])(implicit a: Arbitrary[A]): Unit = {
      val cn = tpe.getType.getTypeName
      describe(s"${cn}") {
        it("is identical after multiple serialization round-trips.") {
          forAll(minSuccessful(10)) { value: A =>
            val encoded: String = json.writeValueAsString(value)
            val decoded: A = json.readValue(encoded, tpe)
            decoded should equal(value)

            val recoded: String = json.writeValueAsString(decoded)
            val redecoded: A = json.readValue(recoded, tpe)
            redecoded should equal(value)
          }
        }
      }
    }

    test(new TypeReference[AAGUID]() {})
    test(new TypeReference[AAID]() {})
    test(new TypeReference[AlternativeDescriptions]() {})
    test(new TypeReference[AttachmentHint]() {})
    test(new TypeReference[AuthenticationAlgorithm]() {})
    test(new TypeReference[AuthenticatorAttestationType]() {})
    test(new TypeReference[AuthenticatorGetInfo]() {})
    test(new TypeReference[AuthenticatorStatus]() {})
    test(new TypeReference[BiometricAccuracyDescriptor]() {})
    test(new TypeReference[BiometricStatusReport]() {})
    test(new TypeReference[CodeAccuracyDescriptor]() {})
    test(new TypeReference[CtapCertificationId]() {})
    test(new TypeReference[CtapPinUvAuthProtocolVersion]() {})
    test(new TypeReference[CtapVersion]() {})
    test(new TypeReference[DisplayPNGCharacteristicsDescriptor]() {})
    test(new TypeReference[ExtensionDescriptor]() {})
    test(new TypeReference[MetadataBLOBHeader]() {})
    test(new TypeReference[MetadataBLOBPayload]() {})
    test(new TypeReference[MetadataBLOBPayloadEntry]() {})
    test(new TypeReference[MetadataStatement]() {})
    test(new TypeReference[PatternAccuracyDescriptor]() {})
    test(new TypeReference[ProtocolFamily]() {})
    test(new TypeReference[PublicKeyRepresentationFormat]() {})
    test(new TypeReference[RgbPaletteEntry]() {})
    test(new TypeReference[StatusReport]() {})
    test(new TypeReference[SupportedCtapOptions]() {})
    test(new TypeReference[TransactionConfirmationDisplayType]() {})
    test(new TypeReference[VerificationMethodDescriptor]() {})
    test(new TypeReference[Version]() {})
  }

}
