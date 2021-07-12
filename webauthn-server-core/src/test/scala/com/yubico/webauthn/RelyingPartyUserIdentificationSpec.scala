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

import com.fasterxml.jackson.databind.node.ObjectNode
import com.yubico.internal.util.scala.JavaConverters._
import com.yubico.webauthn.data.AuthenticatorAssertionResponse
import com.yubico.webauthn.data.ByteArray
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs
import com.yubico.webauthn.data.CollectedClientData
import com.yubico.webauthn.data.PublicKeyCredential
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor
import com.yubico.webauthn.data.RelyingPartyIdentity
import org.junit.runner.RunWith
import org.scalatest.FunSpec
import org.scalatest.Matchers
import org.scalatestplus.junit.JUnitRunner

import java.security.KeyPair
import java.security.interfaces.ECPublicKey
import java.util.Optional
import scala.jdk.CollectionConverters._
import scala.util.Failure
import scala.util.Success
import scala.util.Try

@RunWith(classOf[JUnitRunner])
class RelyingPartyUserIdentificationSpec extends FunSpec with Matchers {

  private object Defaults {

    val rpId =
      RelyingPartyIdentity.builder().id("localhost").name("Test party").build()

    // These values were generated using TestAuthenticator.makeCredentialExample(TestAuthenticator.createCredential())
    val authenticatorData: ByteArray =
      ByteArray.fromHex("49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630100000539")
    val clientDataJson: String =
      """{"challenge":"AAEBAgMFCA0VIjdZEGl5Yls","origin":"localhost","hashAlgorithm":"SHA-256","type":"webauthn.get","tokenBinding":{"status":"supported"}}"""
    val credentialId: ByteArray =
      ByteArray.fromBase64Url("aqFjEQkzH8I55SnmIyNM632MsPI_qZ60aGTSHZMwcKY")
    val credentialKey: KeyPair = TestAuthenticator.importEcKeypair(
      privateBytes =
        ByteArray.fromHex("308193020100301306072a8648ce3d020106082a8648ce3d0301070479307702010104206a88f478910df685bc0cfcc2077e64fb3a8ba770fb23fbbcd1f6572ce35cf360a00a06082a8648ce3d030107a14403420004d8020a2ec718c2c595bb890fcdaf9b81cc742118efdbb8812ac4a9dd5ace2990ec22a48faf1544df0fe5fe0e2e7a69720e63a83d7f46aa022f1323eaf7967762"),
      publicBytes =
        ByteArray.fromHex("3059301306072a8648ce3d020106082a8648ce3d03010703420004d8020a2ec718c2c595bb890fcdaf9b81cc742118efdbb8812ac4a9dd5ace2990ec22a48faf1544df0fe5fe0e2e7a69720e63a83d7f46aa022f1323eaf7967762"),
    )
    val signature: ByteArray =
      ByteArray.fromHex("30450221008d478e4c24894d261c7fd3790363ba9687facf4dd1d59610933a2c292cffc3d902205069264c167833d239d6af4c7bf7326c4883fb8c3517a2c86318aa3060d8b441")

    // These values are not signed over
    val userHandle: ByteArray =
      ByteArray.fromHex("6d8972d9603ce4f3fa5d520ce6d024bf")

    // These values are defined by the attestationObject and clientDataJson above
    val clientDataJsonBytes: ByteArray = new ByteArray(
      clientDataJson.getBytes("UTF-8")
    )
    val clientData = new CollectedClientData(clientDataJsonBytes)
    val challenge: ByteArray = clientData.getChallenge
    val requestedExtensions: Option[ObjectNode] = None
    val clientExtensionResults: ClientAssertionExtensionOutputs =
      ClientAssertionExtensionOutputs.builder().build()

    val publicKeyCredential: PublicKeyCredential[
      AuthenticatorAssertionResponse,
      ClientAssertionExtensionOutputs,
    ] = PublicKeyCredential
      .builder()
      .id(credentialId)
      .response(
        AuthenticatorAssertionResponse
          .builder()
          .authenticatorData(authenticatorData)
          .clientDataJSON(clientDataJsonBytes)
          .signature(signature)
          .build()
      )
      .clientExtensionResults(clientExtensionResults)
      .build()

    val username = "foo-user"

    def defaultResponse(
        userHandle: Option[ByteArray] = None
    ): AuthenticatorAssertionResponse =
      AuthenticatorAssertionResponse
        .builder()
        .authenticatorData(authenticatorData)
        .clientDataJSON(clientDataJsonBytes)
        .signature(signature)
        .userHandle(userHandle.asJava)
        .build()

    def defaultPublicKeyCredential(
        credentialId: ByteArray = Defaults.credentialId,
        response: Option[AuthenticatorAssertionResponse] = None,
        userHandle: Option[ByteArray] = None,
    ): PublicKeyCredential[
      AuthenticatorAssertionResponse,
      ClientAssertionExtensionOutputs,
    ] =
      PublicKeyCredential
        .builder()
        .id(credentialId)
        .response(response getOrElse defaultResponse(userHandle = userHandle))
        .clientExtensionResults(clientExtensionResults)
        .build()
  }

  describe("The assertion ceremony") {

    val rp = RelyingParty
      .builder()
      .identity(Defaults.rpId)
      .credentialRepository(
        new CredentialRepository {
          override def getCredentialIdsForUsername(username: String) =
            if (username == Defaults.username)
              Set(
                PublicKeyCredentialDescriptor
                  .builder()
                  .id(Defaults.credentialId)
                  .build()
              ).asJava
            else
              Set.empty.asJava

          override def lookup(credId: ByteArray, lookupUserHandle: ByteArray) =
            if (credId == Defaults.credentialId)
              Some(
                RegisteredCredential
                  .builder()
                  .credentialId(Defaults.credentialId)
                  .userHandle(Defaults.userHandle)
                  .publicKeyCose(
                    WebAuthnTestCodecs.ecPublicKeyToCose(
                      Defaults.credentialKey.getPublic.asInstanceOf[ECPublicKey]
                    )
                  )
                  .signatureCount(0)
                  .build()
              ).asJava
            else
              None.asJava

          override def lookupAll(credId: ByteArray) = ???
          override def getUserHandleForUsername(username: String)
              : Optional[ByteArray] =
            if (username == Defaults.username)
              Some(Defaults.userHandle).asJava
            else
              None.asJava
          override def getUsernameForUserHandle(userHandle: ByteArray)
              : Optional[String] =
            if (userHandle == Defaults.userHandle)
              Some(Defaults.username).asJava
            else
              None.asJava
        }
      )
      .preferredPubkeyParams(Nil.asJava)
      .origins(Set(Defaults.rpId.getId).asJava)
      .allowUntrustedAttestation(false)
      .validateSignatureCounter(true)
      .build()

    it("succeeds for the default test case if a username was given.") {
      val request = rp.startAssertion(
        StartAssertionOptions
          .builder()
          .username(Defaults.username)
          .build()
      )
      val deterministicRequest =
        request.toBuilder
          .publicKeyCredentialRequestOptions(
            request.getPublicKeyCredentialRequestOptions.toBuilder
              .challenge(Defaults.challenge)
              .build()
          )
          .build()

      val result = Try(
        rp.finishAssertion(
          FinishAssertionOptions
            .builder()
            .request(deterministicRequest)
            .response(Defaults.publicKeyCredential)
            .build()
        )
      )

      result shouldBe a[Success[_]]
    }

    it("succeeds if username was not given but userHandle was returned.") {
      val request = rp.startAssertion(StartAssertionOptions.builder().build())
      val deterministicRequest =
        request.toBuilder
          .publicKeyCredentialRequestOptions(
            request.getPublicKeyCredentialRequestOptions.toBuilder
              .challenge(Defaults.challenge)
              .build()
          )
          .build()

      val response: PublicKeyCredential[
        AuthenticatorAssertionResponse,
        ClientAssertionExtensionOutputs,
      ] = Defaults.defaultPublicKeyCredential(
        userHandle = Some(Defaults.userHandle)
      )

      val result = Try(
        rp.finishAssertion(
          FinishAssertionOptions
            .builder()
            .request(deterministicRequest)
            .response(response)
            .build()
        )
      )

      result shouldBe a[Success[_]]
    }

    it("fails for the default test case if no username was given and no userHandle returned.") {
      val request = rp.startAssertion(StartAssertionOptions.builder().build())
      val deterministicRequest =
        request.toBuilder
          .publicKeyCredentialRequestOptions(
            request.getPublicKeyCredentialRequestOptions.toBuilder
              .challenge(Defaults.challenge)
              .build()
          )
          .build()

      val result = Try(
        rp.finishAssertion(
          FinishAssertionOptions
            .builder()
            .request(deterministicRequest)
            .response(Defaults.publicKeyCredential)
            .build()
        )
      )

      result shouldBe a[Failure[_]]
    }

  }

}
