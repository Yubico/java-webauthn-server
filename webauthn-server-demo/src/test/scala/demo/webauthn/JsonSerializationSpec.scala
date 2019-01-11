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

package demo.webauthn

import com.yubico.internal.util.WebAuthnCodecs
import com.yubico.webauthn.RegistrationTestData
import com.yubico.webauthn.data.AuthenticatorAttestationResponse
import demo.webauthn.data.RegistrationResponse
import org.junit.runner.RunWith
import org.scalatest.FunSpec
import org.scalatest.Matchers
import org.scalatest.junit.JUnitRunner

@RunWith(classOf[JUnitRunner])
class JsonSerializationSpec extends FunSpec with Matchers {

  private val jsonMapper = WebAuthnCodecs.json()

  val testData = RegistrationTestData.FidoU2f.BasicAttestation
  val authenticationAttestationResponseJson = s"""{"attestationObject":"${testData.response.getResponse.getAttestationObject.getBase64Url}","clientDataJSON":"${testData.response.getResponse.getClientDataJSON.getBase64Url}"}"""
  val publicKeyCredentialJson = s"""{"id":"${testData.response.getId.getBase64Url}","response":${authenticationAttestationResponseJson},"clientExtensionResults":{},"type":"public-key"}"""
  val registrationResponseJson = s"""{"requestId":"request1","credential":${publicKeyCredentialJson}}"""

  it("RegistrationResponse can be deserialized from JSON.") {
    val parsed = jsonMapper.readValue(registrationResponseJson, classOf[RegistrationResponse])
    parsed.getCredential should equal (testData.response)
  }

  it("AuthenticatorAttestationResponse can be deserialized from JSON.") {
    val parsed = jsonMapper.readValue(authenticationAttestationResponseJson, classOf[AuthenticatorAttestationResponse])
    parsed should not be null
  }

}
