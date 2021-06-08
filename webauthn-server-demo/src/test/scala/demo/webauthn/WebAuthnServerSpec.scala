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

import com.google.common.cache.Cache
import com.google.common.cache.CacheBuilder
import com.yubico.internal.util.JacksonCodecs
import com.yubico.internal.util.scala.JavaConverters._
import com.yubico.webauthn.RegisteredCredential
import com.yubico.webauthn.RegistrationTestData
import com.yubico.webauthn.TestAuthenticator
import com.yubico.webauthn.WebAuthnTestCodecs
import com.yubico.webauthn.data.ByteArray
import com.yubico.webauthn.data.CollectedClientData
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions
import com.yubico.webauthn.data.RelyingPartyIdentity
import com.yubico.webauthn.extension.appid.AppId
import demo.webauthn.data.AssertionRequestWrapper
import demo.webauthn.data.CredentialRegistration
import demo.webauthn.data.RegistrationRequest
import org.junit.runner.RunWith
import org.scalatest.FunSpec
import org.scalatest.Matchers
import org.scalatestplus.junit.JUnitRunner

import java.security.KeyPair
import java.security.interfaces.ECPublicKey
import java.time.Instant
import java.util.Optional
import java.util.concurrent.TimeUnit
import scala.jdk.CollectionConverters._

@RunWith(classOf[JUnitRunner])
class WebAuthnServerSpec extends FunSpec with Matchers {

  private val jsonMapper = JacksonCodecs.json()
  private val username = "foo-user"
  private val displayName = "Foo User"
  private val credentialNickname = Some("My Lovely Credential").asJava
  private val requireResidentKey = false
  private val requestId = ByteArray.fromBase64Url("request1")
  private val rpId =
    RelyingPartyIdentity.builder().id("localhost").name("Test party").build()
  private val origins = Set("localhost").asJava
  private val appId = Optional.empty[AppId]

  describe("WebAuthnServer") {

    describe("registration") {

      it("has a start method whose output can be serialized to JSON.") {
        val server = newServer
        val request = server.startRegistration(
          username,
          displayName,
          credentialNickname,
          requireResidentKey,
          Optional.empty(),
        )
        val json = jsonMapper.writeValueAsString(request.right.get)

        json should not be null
      }

      it("has a finish method which accepts and outputs JSON.") {
        val requestId = ByteArray.fromBase64Url("request1")

        val server = newServerWithRegistrationRequest(
          RegistrationTestData.FidoU2f.BasicAttestation
        )

        val authenticationAttestationResponseJson =
          """{"attestationObject":"v2hhdXRoRGF0YVikSZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAFOQABAgMEBQYHCAkKCwwNDg8AIIjjhj6nH3qL2QF3tkUogilFykuaXjJTw35O4m-0NSX0pSJYIA5Nt8eYkLco-NQfKPXaA6dD9UfX_SHaYo-L-YQb78HsAyYBAiFYIOuzRl1o1Hem2jVRYhjkbSeIydhqLln9iltAgsDYjXRTIAFjZm10aGZpZG8tdTJmZ2F0dFN0bXS_Y3g1Y59ZAekwggHlMIIBjKADAgECAgIFOTAKBggqhkjOPQQDAjBqMSYwJAYDVQQDDB1ZdWJpY28gV2ViQXV0aG4gdW5pdCB0ZXN0cyBDQTEPMA0GA1UECgwGWXViaWNvMSIwIAYDVQQLDBlBdXRoZW50aWNhdG9yIEF0dGVzdGF0aW9uMQswCQYDVQQGEwJTRTAeFw0xODA5MDYxNzQyMDBaFw0xODA5MDYxNzQyMDBaMGcxIzAhBgNVBAMMGll1YmljbyBXZWJBdXRobiB1bml0IHRlc3RzMQ8wDQYDVQQKDAZZdWJpY28xIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xCzAJBgNVBAYTAlNFMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEJ-8bFED9TnFhaArujgB0foNaV4gQIulP1mC5DO1wvSByw4eOyXujpPHkTw9y5e5J2J3N9coSReZJgBRpvFzYD6MlMCMwIQYLKwYBBAGC5RwBAQQEEgQQAAECAwQFBgcICQoLDA0ODzAKBggqhkjOPQQDAgNHADBEAiB4bL25EH06vPBOVnReObXrS910ARVOLJPPnKNoZbe64gIgX1Rg5oydH45zEMEVDjNPStwv6Z3nE_isMeY-szlQhv3_Y3NpZ1hHMEUCIQDBs1nbSuuKQ6yoHMQoRp8eCT_HZvR45F_aVP6qFX_wKgIgMCL58bv-crkLwTwiEL9ibCV4nDYM-DZuW5_BFCJbcxn__w","clientDataJSON":"eyJjaGFsbGVuZ2UiOiJBQUVCQWdNRkNBMFZJamRaRUdsNVlscyIsIm9yaWdpbiI6ImxvY2FsaG9zdCIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUiLCJ0b2tlbkJpbmRpbmciOnsic3RhdHVzIjoic3VwcG9ydGVkIn19"}"""
        val publicKeyCredentialJson =
          s"""{"id":"iOOGPqcfeovZAXe2RSiCKUXKS5peMlPDfk7ib7Q1JfQ","response":${authenticationAttestationResponseJson},"clientExtensionResults":{},"type":"public-key"}"""
        val responseJson =
          s"""{"requestId":"${requestId.getBase64Url}","credential":${publicKeyCredentialJson}}"""

        val response = server.finishRegistration(responseJson)
        val json = jsonMapper.writeValueAsString(response.right.get)

        json should not be null
      }

    }

    describe("authentication") {

      // These values were generated using TestAuthenticator.makeCredentialExample(TestAuthenticator.createCredential())
      val authenticatorData: ByteArray =
        ByteArray.fromHex("49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630100000539")
      val clientDataJson: String =
        """{"challenge":"AAEBAgMFCA0VIjdZEGl5Yls","origin":"localhost","hashAlgorithm":"SHA-256","type":"webauthn.get","tokenBinding":{"status":"supported"}}"""
      val credentialId: ByteArray =
        RegistrationTestData.FidoU2f.BasicAttestation.response.getId
      val signature: ByteArray =
        ByteArray.fromHex("30450221008d478e4c24894d261c7fd3790363ba9687facf4dd1d59610933a2c292cffc3d902205069264c167833d239d6af4c7bf7326c4883fb8c3517a2c86318aa3060d8b441")

      // These values are defined by the attestationObject and clientDataJson above
      val clientDataJsonBytes: ByteArray =
        new ByteArray(clientDataJson.getBytes("UTF-8"))
      val clientData = new CollectedClientData(clientDataJsonBytes)
      val challenge: ByteArray = clientData.getChallenge
      val privateKeyBytes =
        ByteArray.fromHex("308193020100301306072a8648ce3d020106082a8648ce3d0301070479307702010104206a88f478910df685bc0cfcc2077e64fb3a8ba770fb23fbbcd1f6572ce35cf360a00a06082a8648ce3d030107a14403420004d8020a2ec718c2c595bb890fcdaf9b81cc742118efdbb8812ac4a9dd5ace2990ec22a48faf1544df0fe5fe0e2e7a69720e63a83d7f46aa022f1323eaf7967762")
      val credentialKey: KeyPair = TestAuthenticator.importEcKeypair(
        privateBytes = privateKeyBytes,
        publicBytes =
          ByteArray.fromHex("3059301306072a8648ce3d020106082a8648ce3d03010703420004d8020a2ec718c2c595bb890fcdaf9b81cc742118efdbb8812ac4a9dd5ace2990ec22a48faf1544df0fe5fe0e2e7a69720e63a83d7f46aa022f1323eaf7967762"),
      )

      val testData = RegistrationTestData.FidoU2f.BasicAttestation
        .copy(privateKey = Some(privateKeyBytes))

      it("has a start method whose output can be serialized to JSON.") {
        val server = newServerWithUser(testData)
        val request =
          server.startAuthentication(Optional.of(testData.userId.getName))
        val json = jsonMapper.writeValueAsString(request.right.get)

        json should not be null
      }

      it("has a finish method which accepts and outputs JSON.") {
        val server = newServerWithAuthenticationRequest(
          testData,
          signatureCount = Some(1336),
        )
        val authenticatorAssertionResponseJson =
          s"""{"authenticatorData":"${authenticatorData.getBase64Url}","signature":"${signature.getBase64Url}","clientDataJSON":"${clientDataJsonBytes.getBase64Url}"}"""
        val publicKeyCredentialJson =
          s"""{"id":"${credentialId.getBase64Url}","response":${authenticatorAssertionResponseJson},"clientExtensionResults":{},"type":"public-key"}"""
        val responseJson =
          s"""{"requestId":"${requestId.getBase64Url}","credential":${publicKeyCredentialJson}}"""
        val response = server.finishAuthentication(responseJson)
        val json = jsonMapper.writeValueAsString(response.right.get)

        json should not be null
      }

      it("has a finish method which updates the signature count.") {

        val server = new WebAuthnServer(
          new InMemoryRegistrationStorage(),
          newCache(),
          newCache(),
          rpId,
          Set("https://localhost").asJava,
          appId,
        )

        val (cred, keypair) = {
          val request = server
            .startRegistration(
              username,
              displayName,
              None.asJava,
              false,
              None.asJava,
            )
            .right
            .get
          val (cred, keypair) =
            TestAuthenticator.createUnattestedCredential(challenge =
              request.getPublicKeyCredentialCreationOptions.getChallenge
            )

          val publicKeyCredentialJson =
            JacksonCodecs.json().writeValueAsString(cred)
          val responseJson =
            s"""{"requestId":"${request.getRequestId.getBase64Url}","credential":${publicKeyCredentialJson}}"""
          val response = server.finishRegistration(responseJson)
          response.isRight should be(true)

          (cred, keypair)
        }

        {
          val request =
            server.startAuthentication(Optional.of(username)).right.get
          val assertion = TestAuthenticator.createAssertion(
            challenge =
              request.getPublicKeyCredentialRequestOptions.getChallenge,
            credentialId = cred.getId,
            credentialKey = keypair,
            signatureCount = Some(1340),
          )
          val publicKeyCredentialJson =
            JacksonCodecs.json().writeValueAsString(assertion)
          val responseJson =
            s"""{"requestId":"${request.getRequestId.getBase64Url}","credential":${publicKeyCredentialJson}}"""
          val response = server.finishAuthentication(responseJson)

          response.right.get.getRegistrations.asScala
            .find(_.getCredential.getCredentialId == cred.getId)
            .get
            .getCredential
            .getSignatureCount should equal(1340)
        }

        {
          val request =
            server.startAuthentication(Optional.of(username)).right.get
          val assertion = TestAuthenticator.createAssertion(
            challenge =
              request.getPublicKeyCredentialRequestOptions.getChallenge,
            credentialId = cred.getId,
            credentialKey = keypair,
            signatureCount = Some(1341),
          )
          val publicKeyCredentialJson =
            JacksonCodecs.json().writeValueAsString(assertion)
          val responseJson =
            s"""{"requestId":"${request.getRequestId.getBase64Url}","credential":${publicKeyCredentialJson}}"""
          val response = server.finishAuthentication(responseJson)

          response.right.get.getRegistrations.asScala
            .find(_.getCredential.getCredentialId == cred.getId)
            .get
            .getCredential
            .getSignatureCount should equal(1341)
        }
      }

      def newServerWithAuthenticationRequest(
          testData: RegistrationTestData,
          signatureCount: Option[Long] = None,
      ) = {
        val assertionRequests: Cache[ByteArray, AssertionRequestWrapper] =
          newCache()

        assertionRequests.put(
          requestId,
          new AssertionRequestWrapper(
            requestId,
            com.yubico.webauthn.AssertionRequest
              .builder()
              .publicKeyCredentialRequestOptions(
                PublicKeyCredentialRequestOptions
                  .builder()
                  .challenge(challenge)
                  .rpId(rpId.getId)
                  .build()
              )
              .username(Some(testData.userId.getName).asJava)
              .build(),
          ),
        )

        val userStorage = makeUserStorage(
          testData,
          credentialPubkey = Some(
            WebAuthnTestCodecs.ecPublicKeyToCose(
              credentialKey.getPublic.asInstanceOf[ECPublicKey]
            )
          ),
          signatureCount = signatureCount,
        )
        new WebAuthnServer(
          userStorage,
          newCache(),
          assertionRequests,
          rpId,
          origins,
          appId,
        )
      }
    }

  }

  private def newServer = new WebAuthnServer

  private def newServerWithUser(
      testData: RegistrationTestData,
      origins: java.util.Set[String] = origins,
  ) = {
    val userStorage: RegistrationStorage = makeUserStorage(testData)

    new WebAuthnServer(
      userStorage,
      newCache(),
      newCache(),
      rpId,
      origins,
      appId,
    )
  }

  private def makeUserStorage(
      testData: RegistrationTestData,
      credentialPubkey: Option[ByteArray] = None,
      signatureCount: Option[Long] = None,
  ) = {
    val storage = new InMemoryRegistrationStorage()
    storage.addRegistrationByUsername(
      testData.userId.getName,
      CredentialRegistration
        .builder()
        .userIdentity(testData.request.getUser)
        .credentialNickname(credentialNickname)
        .registrationTime(Instant.parse("2018-07-06T15:07:15Z"))
        .credential(
          RegisteredCredential
            .builder()
            .credentialId(testData.response.getId)
            .userHandle(testData.request.getUser.getId)
            .publicKeyCose(
              credentialPubkey getOrElse testData.response.getResponse.getParsedAuthenticatorData.getAttestedCredentialData.get.getCredentialPublicKey
            )
            .signatureCount(
              signatureCount getOrElse testData.response.getResponse.getAttestation.getAuthenticatorData.getSignatureCounter
            )
            .build()
        )
        .build(),
    )

    storage
  }

  private def newServerWithRegistrationRequest(
      testData: RegistrationTestData
  ) = {
    val registrationRequests: Cache[ByteArray, RegistrationRequest] = newCache()

    registrationRequests.put(
      requestId,
      new RegistrationRequest(
        testData.userId.getName,
        credentialNickname,
        requestId,
        testData.request,
        Optional.empty(),
      ),
    )

    new WebAuthnServer(
      new InMemoryRegistrationStorage,
      registrationRequests,
      newCache(),
      rpId,
      origins,
      appId,
    )
  }

  private def newCache[K <: Object, V <: Object](): Cache[K, V] =
    CacheBuilder
      .newBuilder()
      .maximumSize(100)
      .expireAfterAccess(10, TimeUnit.MINUTES)
      .build()

}
