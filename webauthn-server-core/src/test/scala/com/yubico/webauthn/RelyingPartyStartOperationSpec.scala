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
import com.yubico.scalacheck.gen.JavaGenerators._
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor
import com.yubico.webauthn.data.ByteArray
import com.yubico.webauthn.data.UserIdentity
import com.yubico.webauthn.data.RelyingPartyIdentity
import com.yubico.webauthn.data.PublicKeyCredentialParameters
import com.yubico.webauthn.data.Generators._
import com.yubico.webauthn.extension.appid.AppId
import com.yubico.webauthn.extension.appid.Generators._
import org.junit.runner.RunWith
import org.scalacheck.Arbitrary._
import org.scalatest.FunSpec
import org.scalatest.Matchers
import org.scalatest.junit.JUnitRunner
import org.scalatest.prop.GeneratorDrivenPropertyChecks

import scala.collection.JavaConverters._


@RunWith(classOf[JUnitRunner])
class RelyingPartyStartOperationSpec extends FunSpec with Matchers with GeneratorDrivenPropertyChecks {

  def credRepo(credentials: Set[PublicKeyCredentialDescriptor]): CredentialRepository = new CredentialRepository {
    override def getCredentialIdsForUsername(username: String): java.util.Set[PublicKeyCredentialDescriptor] = credentials.asJava
    override def getUserHandleForUsername(username: String): Optional[ByteArray] = ???
    override def getUsernameForUserHandle(userHandleBase64: ByteArray): Optional[String] = ???
    override def lookup(credentialId: ByteArray, userHandle: ByteArray): Optional[RegisteredCredential] = ???
    override def lookupAll(credentialId: ByteArray): java.util.Set[RegisteredCredential] = ???
  }

  def relyingParty(
    appId: Optional[AppId] = None.asJava,
    credentials: Set[PublicKeyCredentialDescriptor] = Set.empty
  ): RelyingParty = RelyingParty
    .builder(
      rpId,
      List(PublicKeyCredentialParameters.ES256).asJava,
      Nil.asJava,
      credRepo(credentials)
    )
    .appId(appId)
    .build()

  val rpId = RelyingPartyIdentity.builder()
    .id("localhost")
    .name("Test")
    .build()

  val userId = UserIdentity.builder()
    .name("foo")
    .displayName("Foo")
    .id(new ByteArray(Array(0, 1 ,2, 3)))
    .build()

  describe("RelyingParty.startRegistration") {

    it("sets excludeCredentials automatically.") {
      forAll { credentials: Set[PublicKeyCredentialDescriptor] =>
        val rp = relyingParty(credentials = credentials)
        val result = rp.startRegistration(StartRegistrationOptions.builder(userId)
          .build()
        )

        result.getExcludeCredentials.asScala.map(_.asScala) should equal (Some(credentials))
      }
    }

    it("sets challenge randomly.") {
      val rp = relyingParty()

      val request1 = rp.startRegistration(StartRegistrationOptions.builder(userId).build())
      val request2 = rp.startRegistration(StartRegistrationOptions.builder(userId).build())

      request1.getChallenge should not equal request2.getChallenge
      request1.getChallenge.size should be >= 32
      request2.getChallenge.size should be >= 32
    }

  }

  describe("RelyingParty.startAssertion") {

    it("sets allowCredentials to empty if not given a username.") {
      forAll { credentials: Set[PublicKeyCredentialDescriptor] =>
        val rp = relyingParty(credentials = credentials)
        val result = rp.startAssertion(StartAssertionOptions.builder().build())

        result.getPublicKeyCredentialRequestOptions.getAllowCredentials.asScala shouldBe empty
      }
    }

    it("sets allowCredentials automatically if given a username.") {
      forAll { credentials: Set[PublicKeyCredentialDescriptor] =>
        val rp = relyingParty(credentials = credentials)
        val result = rp.startAssertion(StartAssertionOptions.builder()
          .username(Some(userId.getName).asJava)
          .build()
        )

        result.getPublicKeyCredentialRequestOptions.getAllowCredentials.asScala.map(_.asScala.toSet) should equal (Some(credentials))
      }
    }

    it("sets challenge randomly.") {
      val rp = relyingParty()

      val request1 = rp.startAssertion(StartAssertionOptions.builder().build())
      val request2 = rp.startAssertion(StartAssertionOptions.builder().build())

      request1.getPublicKeyCredentialRequestOptions.getChallenge should not equal request2.getPublicKeyCredentialRequestOptions.getChallenge
      request1.getPublicKeyCredentialRequestOptions.getChallenge.size should be >= 32
      request2.getPublicKeyCredentialRequestOptions.getChallenge.size should be >= 32
    }

    it("sets the appid extension if the RP instance is given an AppId.") {
      forAll { appId: Optional[AppId] =>
        val rp = relyingParty(appId = appId)
        val result = rp.startAssertion(StartAssertionOptions.builder()
          .username(Some(userId.getName).asJava)
          .build()
        )

        result.getPublicKeyCredentialRequestOptions.getExtensions.getAppid should equal (appId)
      }
    }

  }

}
