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

import com.yubico.internal.util.JacksonCodecs
import com.yubico.webauthn.Generators._
import com.yubico.webauthn.data.AssertionExtensionInputs
import com.yubico.webauthn.data.AttestationConveyancePreference
import com.yubico.webauthn.data.AuthenticatorAttachment
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria
import com.yubico.webauthn.data.AuthenticatorTransport
import com.yubico.webauthn.data.ByteArray
import com.yubico.webauthn.data.Generators.Extensions.registrationExtensionInputs
import com.yubico.webauthn.data.Generators._
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor
import com.yubico.webauthn.data.PublicKeyCredentialHint
import com.yubico.webauthn.data.PublicKeyCredentialParameters
import com.yubico.webauthn.data.RegistrationExtensionInputs
import com.yubico.webauthn.data.RelyingPartyIdentity
import com.yubico.webauthn.data.ResidentKeyRequirement
import com.yubico.webauthn.data.UserIdentity
import com.yubico.webauthn.extension.appid.AppId
import com.yubico.webauthn.extension.appid.Generators._
import com.yubico.webauthn.test.Helpers
import org.junit.runner.RunWith
import org.scalacheck.Arbitrary.arbitrary
import org.scalacheck.Gen
import org.scalatest.funspec.AnyFunSpec
import org.scalatest.matchers.should.Matchers
import org.scalatestplus.junit.JUnitRunner
import org.scalatestplus.scalacheck.ScalaCheckDrivenPropertyChecks

import java.util.Optional
import scala.jdk.CollectionConverters._
import scala.jdk.OptionConverters.RichOption
import scala.jdk.OptionConverters.RichOptional

@RunWith(classOf[JUnitRunner])
class RelyingPartyStartOperationSpec
    extends AnyFunSpec
    with Matchers
    with ScalaCheckDrivenPropertyChecks {

  def credRepo(
      credentials: Set[PublicKeyCredentialDescriptor],
      userId: UserIdentity,
  ): CredentialRepository =
    new CredentialRepository {
      override def getCredentialIdsForUsername(
          username: String
      ): java.util.Set[PublicKeyCredentialDescriptor] = credentials.asJava
      override def getUserHandleForUsername(
          username: String
      ): Optional[ByteArray] = ???
      override def getUsernameForUserHandle(
          userHandle: ByteArray
      ): Optional[String] =
        if (userHandle == userId.getId) Some(userId.getName).toJava
        else None.toJava
      override def lookup(
          credentialId: ByteArray,
          userHandle: ByteArray,
      ): Optional[RegisteredCredential] = ???
      override def lookupAll(
          credentialId: ByteArray
      ): java.util.Set[RegisteredCredential] = ???
    }

  val rpId = RelyingPartyIdentity
    .builder()
    .id("localhost")
    .name("Test")
    .build()

  val userId = UserIdentity
    .builder()
    .name("foo")
    .displayName("Foo")
    .id(new ByteArray(Array(0, 1, 2, 3)))
    .build()

  describe("RelyingParty") {
    def relyingParty(
        appId: Option[AppId] = None,
        attestationConveyancePreference: Option[
          AttestationConveyancePreference
        ] = None,
        credentials: Set[PublicKeyCredentialDescriptor] = Set.empty,
        userId: UserIdentity,
    ): RelyingParty = {
      var builder = RelyingParty
        .builder()
        .identity(rpId)
        .credentialRepository(credRepo(credentials, userId))
        .preferredPubkeyParams(List(PublicKeyCredentialParameters.ES256).asJava)
        .origins(Set.empty.asJava)
      appId.foreach { appid => builder = builder.appId(appid) }
      attestationConveyancePreference.foreach { acp =>
        builder = builder.attestationConveyancePreference(acp)
      }
      builder.build()
    }

    describe("startRegistration") {

      it("sets excludeCredentials automatically.") {
        forAll { credentials: Set[PublicKeyCredentialDescriptor] =>
          val rp = relyingParty(credentials = credentials, userId = userId)
          val result = rp.startRegistration(
            StartRegistrationOptions
              .builder()
              .user(userId)
              .build()
          )

          result.getExcludeCredentials.toScala.map(_.asScala) should equal(
            Some(credentials)
          )
        }
      }

      it("sets challenge randomly.") {
        val rp = relyingParty(userId = userId)

        val request1 = rp.startRegistration(
          StartRegistrationOptions.builder().user(userId).build()
        )
        val request2 = rp.startRegistration(
          StartRegistrationOptions.builder().user(userId).build()
        )

        request1.getChallenge should not equal request2.getChallenge
        request1.getChallenge.size should be >= 32
        request2.getChallenge.size should be >= 32
      }

      it("allows setting authenticatorSelection.") {
        val authnrSel = AuthenticatorSelectionCriteria
          .builder()
          .authenticatorAttachment(AuthenticatorAttachment.CROSS_PLATFORM)
          .residentKey(ResidentKeyRequirement.REQUIRED)
          .build()

        val pkcco = relyingParty(userId = userId).startRegistration(
          StartRegistrationOptions
            .builder()
            .user(userId)
            .authenticatorSelection(authnrSel)
            .build()
        )
        pkcco.getAuthenticatorSelection.toScala should equal(Some(authnrSel))
      }

      it("allows setting authenticatorSelection with an Optional value.") {
        val authnrSel = AuthenticatorSelectionCriteria
          .builder()
          .authenticatorAttachment(AuthenticatorAttachment.CROSS_PLATFORM)
          .residentKey(ResidentKeyRequirement.REQUIRED)
          .build()

        val pkccoWith = relyingParty(userId = userId).startRegistration(
          StartRegistrationOptions
            .builder()
            .user(userId)
            .authenticatorSelection(Optional.of(authnrSel))
            .build()
        )
        val pkccoWithout = relyingParty(userId = userId).startRegistration(
          StartRegistrationOptions
            .builder()
            .user(userId)
            .authenticatorSelection(
              Optional.empty[AuthenticatorSelectionCriteria]
            )
            .build()
        )
        pkccoWith.getAuthenticatorSelection.toScala should equal(
          Some(authnrSel)
        )
        pkccoWithout.getAuthenticatorSelection.toScala should equal(None)
      }

      it("uses the RelyingParty setting for attestationConveyancePreference.") {
        forAll { acp: Option[AttestationConveyancePreference] =>
          val pkcco =
            relyingParty(attestationConveyancePreference = acp, userId = userId)
              .startRegistration(
                StartRegistrationOptions
                  .builder()
                  .user(userId)
                  .build()
              )
          pkcco.getAttestation should equal(
            acp getOrElse AttestationConveyancePreference.NONE
          )
        }
      }

      describe("allows setting the hints") {
        val rp = relyingParty(userId = userId)

        it("to string values in the spec or not.") {
          val pkcco = rp.startRegistration(
            StartRegistrationOptions
              .builder()
              .user(userId)
              .hints("hej", "security-key", "hoj", "client-device", "hybrid")
              .build()
          )
          pkcco.getHints.asScala should equal(
            List(
              "hej",
              PublicKeyCredentialHint.SECURITY_KEY.getValue,
              "hoj",
              PublicKeyCredentialHint.CLIENT_DEVICE.getValue,
              PublicKeyCredentialHint.HYBRID.getValue,
            )
          )
        }

        it("to PublicKeyCredentialHint values in the spec or not.") {
          val pkcco = rp.startRegistration(
            StartRegistrationOptions
              .builder()
              .user(userId)
              .hints(
                PublicKeyCredentialHint.of("hej"),
                PublicKeyCredentialHint.HYBRID,
                PublicKeyCredentialHint.SECURITY_KEY,
                PublicKeyCredentialHint.of("hoj"),
                PublicKeyCredentialHint.CLIENT_DEVICE,
              )
              .build()
          )
          pkcco.getHints.asScala should equal(
            List(
              "hej",
              PublicKeyCredentialHint.HYBRID.getValue,
              PublicKeyCredentialHint.SECURITY_KEY.getValue,
              "hoj",
              PublicKeyCredentialHint.CLIENT_DEVICE.getValue,
            )
          )
        }

        it("or not, defaulting to the empty list.") {
          val pkcco = rp.startRegistration(
            StartRegistrationOptions
              .builder()
              .user(userId)
              .build()
          )
          pkcco.getHints.asScala should equal(List())
        }
      }

      it("allows setting the timeout to empty.") {
        val pkcco = relyingParty(userId = userId).startRegistration(
          StartRegistrationOptions
            .builder()
            .user(userId)
            .timeout(Optional.empty[java.lang.Long])
            .build()
        )
        pkcco.getTimeout.toScala shouldBe empty
      }

      it("allows setting the timeout to a positive value.") {
        val rp = relyingParty(userId = userId)

        forAll(Gen.posNum[Long]) { timeout: Long =>
          val pkcco = rp.startRegistration(
            StartRegistrationOptions
              .builder()
              .user(userId)
              .timeout(timeout)
              .build()
          )

          pkcco.getTimeout.toScala should equal(Some(timeout))
        }
      }

      it("does not allow setting the timeout to zero or negative.") {
        an[IllegalArgumentException] should be thrownBy {
          StartRegistrationOptions
            .builder()
            .user(userId)
            .timeout(0)
        }

        an[IllegalArgumentException] should be thrownBy {
          StartRegistrationOptions
            .builder()
            .user(userId)
            .timeout(Optional.of[java.lang.Long](0L))
        }

        forAll(Gen.negNum[Long]) { timeout: Long =>
          an[IllegalArgumentException] should be thrownBy {
            StartRegistrationOptions
              .builder()
              .user(userId)
              .timeout(timeout)
          }

          an[IllegalArgumentException] should be thrownBy {
            StartRegistrationOptions
              .builder()
              .user(userId)
              .timeout(Optional.of[java.lang.Long](timeout))
          }
        }
      }

      it(
        "sets the appidExclude extension if the RP instance is given an AppId."
      ) {
        forAll { appId: AppId =>
          val rp = relyingParty(appId = Some(appId), userId = userId)
          val result = rp.startRegistration(
            StartRegistrationOptions
              .builder()
              .user(userId)
              .build()
          )

          result.getExtensions.getAppidExclude.toScala should equal(Some(appId))
        }
      }

      it("does not set the appidExclude extension if the RP instance is not given an AppId.") {
        val rp = relyingParty(userId = userId)
        val result = rp.startRegistration(
          StartRegistrationOptions
            .builder()
            .user(userId)
            .build()
        )

        result.getExtensions.getAppidExclude.toScala should equal(None)
      }

      it("does not override the appidExclude extension with an empty value if already non-null in StartRegistrationOptions.") {
        forAll { requestAppId: AppId =>
          val rp = relyingParty(appId = None, userId = userId)
          val result = rp.startRegistration(
            StartRegistrationOptions
              .builder()
              .user(userId)
              .extensions(
                RegistrationExtensionInputs
                  .builder()
                  .appidExclude(requestAppId)
                  .build()
              )
              .build()
          )

          result.getExtensions.getAppidExclude.toScala should equal(
            Some(requestAppId)
          )
        }
      }

      it("does not override the appidExclude extension if already non-null in StartRegistrationOptions.") {
        forAll { (requestAppId: AppId, rpAppId: AppId) =>
          whenever(requestAppId != rpAppId) {
            val rp = relyingParty(appId = Some(rpAppId), userId = userId)
            val result = rp.startRegistration(
              StartRegistrationOptions
                .builder()
                .user(userId)
                .extensions(
                  RegistrationExtensionInputs
                    .builder()
                    .appidExclude(requestAppId)
                    .build()
                )
                .build()
            )

            result.getExtensions.getAppidExclude.toScala should equal(
              Some(requestAppId)
            )
          }
        }
      }

      it("by default sets the credProps extension.") {
        forAll(registrationExtensionInputs(credPropsGen = None)) {
          extensions: RegistrationExtensionInputs =>
            val rp = relyingParty(userId = userId)
            val result = rp.startRegistration(
              StartRegistrationOptions
                .builder()
                .user(userId)
                .extensions(extensions)
                .build()
            )

            result.getExtensions.getCredProps should be(true)
        }
      }

      it("does not override the credProps extension if explicitly set to false in StartRegistrationOptions.") {
        forAll(registrationExtensionInputs(credPropsGen = Some(false))) {
          extensions: RegistrationExtensionInputs =>
            val rp = relyingParty(userId = userId)
            val result = rp.startRegistration(
              StartRegistrationOptions
                .builder()
                .user(userId)
                .extensions(extensions)
                .build()
            )

            result.getExtensions.getCredProps should be(false)
        }
      }

      it("by default does not set the uvm extension.") {
        val rp = relyingParty(userId = userId)
        val result = rp.startRegistration(
          StartRegistrationOptions
            .builder()
            .user(userId)
            .build()
        )
        result.getExtensions.getUvm should be(false)
      }

      it("sets the uvm extension if enabled in StartRegistrationOptions.") {
        forAll { extensions: RegistrationExtensionInputs =>
          val rp = relyingParty(userId = userId)
          val result = rp.startRegistration(
            StartRegistrationOptions
              .builder()
              .user(userId)
              .extensions(extensions.toBuilder.uvm().build())
              .build()
          )

          result.getExtensions.getUvm should be(true)
        }
      }

      it("respects the residentKey setting.") {
        val rp = relyingParty(userId = userId)

        val pkccoDiscouraged = rp.startRegistration(
          StartRegistrationOptions
            .builder()
            .user(userId)
            .authenticatorSelection(
              AuthenticatorSelectionCriteria
                .builder()
                .residentKey(ResidentKeyRequirement.DISCOURAGED)
                .build()
            )
            .build()
        )

        val pkccoPreferred = rp.startRegistration(
          StartRegistrationOptions
            .builder()
            .user(userId)
            .authenticatorSelection(
              AuthenticatorSelectionCriteria
                .builder()
                .residentKey(ResidentKeyRequirement.PREFERRED)
                .build()
            )
            .build()
        )

        val pkccoRequired = rp.startRegistration(
          StartRegistrationOptions
            .builder()
            .user(userId)
            .authenticatorSelection(
              AuthenticatorSelectionCriteria
                .builder()
                .residentKey(ResidentKeyRequirement.REQUIRED)
                .build()
            )
            .build()
        )

        val pkccoUnspecified = rp.startRegistration(
          StartRegistrationOptions
            .builder()
            .user(userId)
            .authenticatorSelection(
              AuthenticatorSelectionCriteria.builder().build()
            )
            .build()
        )

        def jsonRequireResidentKey(
            pkcco: PublicKeyCredentialCreationOptions
        ): Option[Boolean] =
          Option(
            JacksonCodecs
              .json()
              .readTree(pkcco.toCredentialsCreateJson)
              .get("publicKey")
              .get("authenticatorSelection")
              .get("requireResidentKey")
          ).map(_.booleanValue)

        pkccoDiscouraged.getAuthenticatorSelection.get.getResidentKey.toScala should be(
          Some(ResidentKeyRequirement.DISCOURAGED)
        )
        jsonRequireResidentKey(pkccoDiscouraged) should be(Some(false))

        pkccoPreferred.getAuthenticatorSelection.get.getResidentKey.toScala should be(
          Some(ResidentKeyRequirement.PREFERRED)
        )
        jsonRequireResidentKey(pkccoPreferred) should be(Some(false))

        pkccoRequired.getAuthenticatorSelection.get.getResidentKey.toScala should be(
          Some(ResidentKeyRequirement.REQUIRED)
        )
        jsonRequireResidentKey(pkccoRequired) should be(Some(true))

        pkccoUnspecified.getAuthenticatorSelection.get.getResidentKey.toScala should be(
          None
        )
        jsonRequireResidentKey(pkccoUnspecified) should be(None)
      }

      it("respects the authenticatorAttachment parameter.") {
        val rp = relyingParty(userId = userId)

        val pkcco = rp.startRegistration(
          StartRegistrationOptions
            .builder()
            .user(userId)
            .authenticatorSelection(
              AuthenticatorSelectionCriteria
                .builder()
                .authenticatorAttachment(AuthenticatorAttachment.CROSS_PLATFORM)
                .build()
            )
            .build()
        )
        val pkccoWith = rp.startRegistration(
          StartRegistrationOptions
            .builder()
            .user(userId)
            .authenticatorSelection(
              AuthenticatorSelectionCriteria
                .builder()
                .authenticatorAttachment(
                  Optional.of(AuthenticatorAttachment.PLATFORM)
                )
                .build()
            )
            .build()
        )
        val pkccoWithout = rp.startRegistration(
          StartRegistrationOptions
            .builder()
            .user(userId)
            .authenticatorSelection(
              AuthenticatorSelectionCriteria
                .builder()
                .authenticatorAttachment(
                  Optional.empty[AuthenticatorAttachment]
                )
                .build()
            )
            .build()
        )

        pkcco.getAuthenticatorSelection.get.getAuthenticatorAttachment.toScala should be(
          Some(AuthenticatorAttachment.CROSS_PLATFORM)
        )
        pkccoWith.getAuthenticatorSelection.get.getAuthenticatorAttachment.toScala should be(
          Some(AuthenticatorAttachment.PLATFORM)
        )
        pkccoWithout.getAuthenticatorSelection.get.getAuthenticatorAttachment.toScala should be(
          None
        )
      }
    }

    describe("startAssertion") {

      it("sets allowCredentials to empty if not given a username nor a user handle.") {
        forAll { credentials: Set[PublicKeyCredentialDescriptor] =>
          val rp = relyingParty(credentials = credentials, userId = userId)
          val result =
            rp.startAssertion(StartAssertionOptions.builder().build())

          result.getPublicKeyCredentialRequestOptions.getAllowCredentials.toScala shouldBe empty
        }
      }

      it("sets allowCredentials automatically if given a username.") {
        forAll { credentials: Set[PublicKeyCredentialDescriptor] =>
          val rp = relyingParty(credentials = credentials, userId = userId)
          val result = rp.startAssertion(
            StartAssertionOptions
              .builder()
              .username(userId.getName)
              .build()
          )

          result.getPublicKeyCredentialRequestOptions.getAllowCredentials.toScala
            .map(_.asScala.toSet) should equal(Some(credentials))
        }
      }

      it("sets allowCredentials automatically if given a user handle.") {
        forAll { credentials: Set[PublicKeyCredentialDescriptor] =>
          val rp = relyingParty(credentials = credentials, userId = userId)
          val result = rp.startAssertion(
            StartAssertionOptions
              .builder()
              .userHandle(userId.getId)
              .build()
          )

          result.getPublicKeyCredentialRequestOptions.getAllowCredentials.toScala
            .map(_.asScala.toSet) should equal(Some(credentials))
        }
      }

      it("passes username through to AssertionRequest.") {
        forAll { username: String =>
          val testCaseUserId = userId.toBuilder.name(username).build()
          val rp = relyingParty(userId = testCaseUserId)
          val result = rp.startAssertion(
            StartAssertionOptions
              .builder()
              .username(testCaseUserId.getName)
              .build()
          )
          result.getUsername.asScala should equal(Some(testCaseUserId.getName))
        }
      }

      it("passes user handle through to AssertionRequest.") {
        forAll { userHandle: ByteArray =>
          val testCaseUserId = userId.toBuilder.id(userHandle).build()
          val rp = relyingParty(userId = testCaseUserId)
          val result = rp.startAssertion(
            StartAssertionOptions
              .builder()
              .userHandle(testCaseUserId.getId)
              .build()
          )
          result.getUserHandle.asScala should equal(Some(testCaseUserId.getId))
        }
      }

      it("includes transports in allowCredentials when available.") {
        forAll(
          Gen.nonEmptyContainerOf[Set, AuthenticatorTransport](
            arbitrary[AuthenticatorTransport]
          ),
          arbitrary[PublicKeyCredentialDescriptor],
          arbitrary[PublicKeyCredentialDescriptor],
          arbitrary[PublicKeyCredentialDescriptor],
        ) {
          (
              cred1Transports: Set[AuthenticatorTransport],
              cred1: PublicKeyCredentialDescriptor,
              cred2: PublicKeyCredentialDescriptor,
              cred3: PublicKeyCredentialDescriptor,
          ) =>
            val rp = relyingParty(
              credentials = Set(
                cred1.toBuilder.transports(cred1Transports.asJava).build(),
                cred2.toBuilder
                  .transports(
                    Optional.of(Set.empty[AuthenticatorTransport].asJava)
                  )
                  .build(),
                cred3.toBuilder
                  .transports(
                    Optional.empty[java.util.Set[AuthenticatorTransport]]
                  )
                  .build(),
              ),
              userId = userId,
            )
            val result = rp.startAssertion(
              StartAssertionOptions
                .builder()
                .username(userId.getName)
                .build()
            )

            val requestCreds =
              result.getPublicKeyCredentialRequestOptions.getAllowCredentials.get.asScala
            requestCreds.head.getTransports.toScala should equal(
              Some(cred1Transports.asJava)
            )
            requestCreds(1).getTransports.toScala should equal(
              Some(Set.empty.asJava)
            )
            requestCreds(2).getTransports.toScala should equal(None)
        }
      }

      it("sets challenge randomly.") {
        val rp = relyingParty(userId = userId)

        val request1 =
          rp.startAssertion(StartAssertionOptions.builder().build())
        val request2 =
          rp.startAssertion(StartAssertionOptions.builder().build())

        request1.getPublicKeyCredentialRequestOptions.getChallenge should not equal request2.getPublicKeyCredentialRequestOptions.getChallenge
        request1.getPublicKeyCredentialRequestOptions.getChallenge.size should be >= 32
        request2.getPublicKeyCredentialRequestOptions.getChallenge.size should be >= 32
      }

      it("sets the appid extension if the RP instance is given an AppId.") {
        forAll { appId: AppId =>
          val rp = relyingParty(appId = Some(appId), userId = userId)
          val result = rp.startAssertion(
            StartAssertionOptions
              .builder()
              .username(userId.getName)
              .build()
          )

          result.getPublicKeyCredentialRequestOptions.getExtensions.getAppid.toScala should equal(
            Some(appId)
          )
        }
      }

      it("does not set the appid extension if the RP instance is not given an AppId.") {
        val rp = relyingParty(userId = userId)
        val result = rp.startAssertion(
          StartAssertionOptions
            .builder()
            .username(userId.getName)
            .build()
        )

        result.getPublicKeyCredentialRequestOptions.getExtensions.getAppid.toScala should equal(
          None
        )
      }

      it("does not override the appid extension with an empty value if already non-null in StartAssertionOptions.") {
        forAll { requestAppId: AppId =>
          val rp = relyingParty(appId = None, userId = userId)
          val result = rp.startAssertion(
            StartAssertionOptions
              .builder()
              .username(userId.getName)
              .extensions(
                AssertionExtensionInputs
                  .builder()
                  .appid(requestAppId)
                  .build()
              )
              .build()
          )

          result.getPublicKeyCredentialRequestOptions.getExtensions.getAppid.toScala should equal(
            Some(requestAppId)
          )
        }
      }

      it("does not override the appid extension if already non-null in StartAssertionOptions.") {
        forAll { (requestAppId: AppId, rpAppId: AppId) =>
          whenever(requestAppId != rpAppId) {
            val rp = relyingParty(appId = Some(rpAppId), userId = userId)
            val result = rp.startAssertion(
              StartAssertionOptions
                .builder()
                .username(userId.getName)
                .extensions(
                  AssertionExtensionInputs
                    .builder()
                    .appid(requestAppId)
                    .build()
                )
                .build()
            )

            result.getPublicKeyCredentialRequestOptions.getExtensions.getAppid.toScala should equal(
              Some(requestAppId)
            )
          }
        }
      }

      it("allows setting the timeout to empty.") {
        val req = relyingParty(userId = userId).startAssertion(
          StartAssertionOptions
            .builder()
            .timeout(Optional.empty[java.lang.Long])
            .build()
        )
        req.getPublicKeyCredentialRequestOptions.getTimeout.toScala shouldBe empty
      }

      it("allows setting the timeout to a positive value.") {
        val rp = relyingParty(userId = userId)

        forAll(Gen.posNum[Long]) { timeout: Long =>
          val req = rp.startAssertion(
            StartAssertionOptions
              .builder()
              .timeout(timeout)
              .build()
          )

          req.getPublicKeyCredentialRequestOptions.getTimeout.toScala should equal(
            Some(timeout)
          )
        }
      }

      it("does not allow setting the timeout to zero or negative.") {
        an[IllegalArgumentException] should be thrownBy {
          StartAssertionOptions
            .builder()
            .timeout(0)
        }

        an[IllegalArgumentException] should be thrownBy {
          StartAssertionOptions
            .builder()
            .timeout(Optional.of[java.lang.Long](0L))
        }

        forAll(Gen.negNum[Long]) { timeout: Long =>
          an[IllegalArgumentException] should be thrownBy {
            StartAssertionOptions
              .builder()
              .timeout(timeout)
          }

          an[IllegalArgumentException] should be thrownBy {
            StartAssertionOptions
              .builder()
              .timeout(Optional.of[java.lang.Long](timeout))
          }
        }
      }

      it("by default does not set the uvm extension.") {
        val rp = relyingParty(userId = userId)
        val result = rp.startAssertion(
          StartAssertionOptions
            .builder()
            .build()
        )
        result.getPublicKeyCredentialRequestOptions.getExtensions.getUvm should be(
          false
        )
      }

      it("sets the uvm extension if enabled in StartRegistrationOptions.") {
        forAll { extensions: AssertionExtensionInputs =>
          val rp = relyingParty(userId = userId)
          val result = rp.startAssertion(
            StartAssertionOptions
              .builder()
              .extensions(extensions.toBuilder.uvm().build())
              .build()
          )

          result.getPublicKeyCredentialRequestOptions.getExtensions.getUvm should be(
            true
          )
        }
      }
    }
  }

  describe("RelyingPartyV2") {
    def relyingParty(
        appId: Option[AppId] = None,
        attestationConveyancePreference: Option[
          AttestationConveyancePreference
        ] = None,
        credentials: Set[PublicKeyCredentialDescriptor] = Set.empty,
        userId: UserIdentity,
        usernameRepository: Boolean = false,
    ): RelyingPartyV2[CredentialRecord] = {
      var builder = RelyingParty
        .builder()
        .identity(rpId)
        .credentialRepositoryV2(
          Helpers.CredentialRepositoryV2.withUsers(
            credentials
              .map(c =>
                (
                  userId,
                  Helpers.credentialRecord(
                    credentialId = c.getId,
                    userHandle = userId.getId,
                    publicKeyCose = ByteArray.fromHex(""),
                    transports = c.getTransports.map(_.asScala.toSet).toScala,
                  ),
                )
              )
              .toList: _*
          )
        )
        .preferredPubkeyParams(List(PublicKeyCredentialParameters.ES256).asJava)
        .origins(Set.empty.asJava)
      if (usernameRepository) {
        builder.usernameRepository(Helpers.UsernameRepository.withUsers(userId))
      }
      appId.foreach { appid => builder = builder.appId(appid) }
      attestationConveyancePreference.foreach { acp =>
        builder = builder.attestationConveyancePreference(acp)
      }
      builder.build()
    }

    describe("startRegistration") {

      it("sets excludeCredentials automatically.") {
        forAll { credentials: Set[PublicKeyCredentialDescriptor] =>
          val rp = relyingParty(credentials = credentials, userId = userId)
          val result = rp.startRegistration(
            StartRegistrationOptions
              .builder()
              .user(userId)
              .build()
          )

          result.getExcludeCredentials.toScala.map(_.asScala) should equal(
            Some(credentials)
          )
        }
      }

      it("sets challenge randomly.") {
        val rp = relyingParty(userId = userId)

        val request1 = rp.startRegistration(
          StartRegistrationOptions.builder().user(userId).build()
        )
        val request2 = rp.startRegistration(
          StartRegistrationOptions.builder().user(userId).build()
        )

        request1.getChallenge should not equal request2.getChallenge
        request1.getChallenge.size should be >= 32
        request2.getChallenge.size should be >= 32
      }

      it("allows setting authenticatorSelection.") {
        val authnrSel = AuthenticatorSelectionCriteria
          .builder()
          .authenticatorAttachment(AuthenticatorAttachment.CROSS_PLATFORM)
          .residentKey(ResidentKeyRequirement.REQUIRED)
          .build()

        val pkcco = relyingParty(userId = userId).startRegistration(
          StartRegistrationOptions
            .builder()
            .user(userId)
            .authenticatorSelection(authnrSel)
            .build()
        )
        pkcco.getAuthenticatorSelection.toScala should equal(Some(authnrSel))
      }

      it("allows setting authenticatorSelection with an Optional value.") {
        val authnrSel = AuthenticatorSelectionCriteria
          .builder()
          .authenticatorAttachment(AuthenticatorAttachment.CROSS_PLATFORM)
          .residentKey(ResidentKeyRequirement.REQUIRED)
          .build()

        val pkccoWith = relyingParty(userId = userId).startRegistration(
          StartRegistrationOptions
            .builder()
            .user(userId)
            .authenticatorSelection(Optional.of(authnrSel))
            .build()
        )
        val pkccoWithout = relyingParty(userId = userId).startRegistration(
          StartRegistrationOptions
            .builder()
            .user(userId)
            .authenticatorSelection(
              Optional.empty[AuthenticatorSelectionCriteria]
            )
            .build()
        )
        pkccoWith.getAuthenticatorSelection.toScala should equal(
          Some(authnrSel)
        )
        pkccoWithout.getAuthenticatorSelection.toScala should equal(None)
      }

      it("uses the RelyingParty setting for attestationConveyancePreference.") {
        forAll { acp: Option[AttestationConveyancePreference] =>
          val pkcco =
            relyingParty(attestationConveyancePreference = acp, userId = userId)
              .startRegistration(
                StartRegistrationOptions
                  .builder()
                  .user(userId)
                  .build()
              )
          pkcco.getAttestation should equal(
            acp getOrElse AttestationConveyancePreference.NONE
          )
        }
      }

      describe("allows setting the hints") {
        val rp = relyingParty(userId = userId)

        it("to string values in the spec or not.") {
          val pkcco = rp.startRegistration(
            StartRegistrationOptions
              .builder()
              .user(userId)
              .hints("hej", "security-key", "hoj", "client-device", "hybrid")
              .build()
          )
          pkcco.getHints.asScala should equal(
            List(
              "hej",
              PublicKeyCredentialHint.SECURITY_KEY.getValue,
              "hoj",
              PublicKeyCredentialHint.CLIENT_DEVICE.getValue,
              PublicKeyCredentialHint.HYBRID.getValue,
            )
          )
        }

        it("to PublicKeyCredentialHint values in the spec or not.") {
          val pkcco = rp.startRegistration(
            StartRegistrationOptions
              .builder()
              .user(userId)
              .hints(
                PublicKeyCredentialHint.of("hej"),
                PublicKeyCredentialHint.HYBRID,
                PublicKeyCredentialHint.SECURITY_KEY,
                PublicKeyCredentialHint.of("hoj"),
                PublicKeyCredentialHint.CLIENT_DEVICE,
              )
              .build()
          )
          pkcco.getHints.asScala should equal(
            List(
              "hej",
              PublicKeyCredentialHint.HYBRID.getValue,
              PublicKeyCredentialHint.SECURITY_KEY.getValue,
              "hoj",
              PublicKeyCredentialHint.CLIENT_DEVICE.getValue,
            )
          )
        }

        it("or not, defaulting to the empty list.") {
          val pkcco = rp.startRegistration(
            StartRegistrationOptions.builder().user(userId).build()
          )
          pkcco.getHints.asScala should equal(List())
        }
      }

      it("allows setting the timeout to empty.") {
        val pkcco = relyingParty(userId = userId).startRegistration(
          StartRegistrationOptions
            .builder()
            .user(userId)
            .timeout(Optional.empty[java.lang.Long])
            .build()
        )
        pkcco.getTimeout.toScala shouldBe empty
      }

      it("allows setting the timeout to a positive value.") {
        val rp = relyingParty(userId = userId)

        forAll(Gen.posNum[Long]) { timeout: Long =>
          val pkcco = rp.startRegistration(
            StartRegistrationOptions
              .builder()
              .user(userId)
              .timeout(timeout)
              .build()
          )

          pkcco.getTimeout.toScala should equal(Some(timeout))
        }
      }

      it("does not allow setting the timeout to zero or negative.") {
        an[IllegalArgumentException] should be thrownBy {
          StartRegistrationOptions
            .builder()
            .user(userId)
            .timeout(0)
        }

        an[IllegalArgumentException] should be thrownBy {
          StartRegistrationOptions
            .builder()
            .user(userId)
            .timeout(Optional.of[java.lang.Long](0L))
        }

        forAll(Gen.negNum[Long]) { timeout: Long =>
          an[IllegalArgumentException] should be thrownBy {
            StartRegistrationOptions
              .builder()
              .user(userId)
              .timeout(timeout)
          }

          an[IllegalArgumentException] should be thrownBy {
            StartRegistrationOptions
              .builder()
              .user(userId)
              .timeout(Optional.of[java.lang.Long](timeout))
          }
        }
      }

      it(
        "sets the appidExclude extension if the RP instance is given an AppId."
      ) {
        forAll { appId: AppId =>
          val rp = relyingParty(appId = Some(appId), userId = userId)
          val result = rp.startRegistration(
            StartRegistrationOptions
              .builder()
              .user(userId)
              .build()
          )

          result.getExtensions.getAppidExclude.toScala should equal(Some(appId))
        }
      }

      it("does not set the appidExclude extension if the RP instance is not given an AppId.") {
        val rp = relyingParty(userId = userId)
        val result = rp.startRegistration(
          StartRegistrationOptions
            .builder()
            .user(userId)
            .build()
        )

        result.getExtensions.getAppidExclude.toScala should equal(None)
      }

      it("does not override the appidExclude extension with an empty value if already non-null in StartRegistrationOptions.") {
        forAll { requestAppId: AppId =>
          val rp = relyingParty(appId = None, userId = userId)
          val result = rp.startRegistration(
            StartRegistrationOptions
              .builder()
              .user(userId)
              .extensions(
                RegistrationExtensionInputs
                  .builder()
                  .appidExclude(requestAppId)
                  .build()
              )
              .build()
          )

          result.getExtensions.getAppidExclude.toScala should equal(
            Some(requestAppId)
          )
        }
      }

      it("does not override the appidExclude extension if already non-null in StartRegistrationOptions.") {
        forAll { (requestAppId: AppId, rpAppId: AppId) =>
          whenever(requestAppId != rpAppId) {
            val rp = relyingParty(appId = Some(rpAppId), userId = userId)
            val result = rp.startRegistration(
              StartRegistrationOptions
                .builder()
                .user(userId)
                .extensions(
                  RegistrationExtensionInputs
                    .builder()
                    .appidExclude(requestAppId)
                    .build()
                )
                .build()
            )

            result.getExtensions.getAppidExclude.toScala should equal(
              Some(requestAppId)
            )
          }
        }
      }

      it("by default sets the credProps extension.") {
        forAll(registrationExtensionInputs(credPropsGen = None)) {
          extensions: RegistrationExtensionInputs =>
            val rp = relyingParty(userId = userId)
            val result = rp.startRegistration(
              StartRegistrationOptions
                .builder()
                .user(userId)
                .extensions(extensions)
                .build()
            )

            result.getExtensions.getCredProps should be(true)
        }
      }

      it("does not override the credProps extension if explicitly set to false in StartRegistrationOptions.") {
        forAll(registrationExtensionInputs(credPropsGen = Some(false))) {
          extensions: RegistrationExtensionInputs =>
            val rp = relyingParty(userId = userId)
            val result = rp.startRegistration(
              StartRegistrationOptions
                .builder()
                .user(userId)
                .extensions(extensions)
                .build()
            )

            result.getExtensions.getCredProps should be(false)
        }
      }

      it("by default does not set the uvm extension.") {
        val rp = relyingParty(userId = userId)
        val result = rp.startRegistration(
          StartRegistrationOptions
            .builder()
            .user(userId)
            .build()
        )
        result.getExtensions.getUvm should be(false)
      }

      it("sets the uvm extension if enabled in StartRegistrationOptions.") {
        forAll { extensions: RegistrationExtensionInputs =>
          val rp = relyingParty(userId = userId)
          val result = rp.startRegistration(
            StartRegistrationOptions
              .builder()
              .user(userId)
              .extensions(extensions.toBuilder.uvm().build())
              .build()
          )

          result.getExtensions.getUvm should be(true)
        }
      }

      it("respects the residentKey setting.") {
        val rp = relyingParty(userId = userId)

        val pkccoDiscouraged = rp.startRegistration(
          StartRegistrationOptions
            .builder()
            .user(userId)
            .authenticatorSelection(
              AuthenticatorSelectionCriteria
                .builder()
                .residentKey(ResidentKeyRequirement.DISCOURAGED)
                .build()
            )
            .build()
        )

        val pkccoPreferred = rp.startRegistration(
          StartRegistrationOptions
            .builder()
            .user(userId)
            .authenticatorSelection(
              AuthenticatorSelectionCriteria
                .builder()
                .residentKey(ResidentKeyRequirement.PREFERRED)
                .build()
            )
            .build()
        )

        val pkccoRequired = rp.startRegistration(
          StartRegistrationOptions
            .builder()
            .user(userId)
            .authenticatorSelection(
              AuthenticatorSelectionCriteria
                .builder()
                .residentKey(ResidentKeyRequirement.REQUIRED)
                .build()
            )
            .build()
        )

        val pkccoUnspecified = rp.startRegistration(
          StartRegistrationOptions
            .builder()
            .user(userId)
            .authenticatorSelection(
              AuthenticatorSelectionCriteria.builder().build()
            )
            .build()
        )

        def jsonRequireResidentKey(
            pkcco: PublicKeyCredentialCreationOptions
        ): Option[Boolean] =
          Option(
            JacksonCodecs
              .json()
              .readTree(pkcco.toCredentialsCreateJson)
              .get("publicKey")
              .get("authenticatorSelection")
              .get("requireResidentKey")
          ).map(_.booleanValue)

        pkccoDiscouraged.getAuthenticatorSelection.get.getResidentKey.toScala should be(
          Some(ResidentKeyRequirement.DISCOURAGED)
        )
        jsonRequireResidentKey(pkccoDiscouraged) should be(Some(false))

        pkccoPreferred.getAuthenticatorSelection.get.getResidentKey.toScala should be(
          Some(ResidentKeyRequirement.PREFERRED)
        )
        jsonRequireResidentKey(pkccoPreferred) should be(Some(false))

        pkccoRequired.getAuthenticatorSelection.get.getResidentKey.toScala should be(
          Some(ResidentKeyRequirement.REQUIRED)
        )
        jsonRequireResidentKey(pkccoRequired) should be(Some(true))

        pkccoUnspecified.getAuthenticatorSelection.get.getResidentKey.toScala should be(
          None
        )
        jsonRequireResidentKey(pkccoUnspecified) should be(None)
      }

      it("respects the authenticatorAttachment parameter.") {
        val rp = relyingParty(userId = userId)

        val pkcco = rp.startRegistration(
          StartRegistrationOptions
            .builder()
            .user(userId)
            .authenticatorSelection(
              AuthenticatorSelectionCriteria
                .builder()
                .authenticatorAttachment(AuthenticatorAttachment.CROSS_PLATFORM)
                .build()
            )
            .build()
        )
        val pkccoWith = rp.startRegistration(
          StartRegistrationOptions
            .builder()
            .user(userId)
            .authenticatorSelection(
              AuthenticatorSelectionCriteria
                .builder()
                .authenticatorAttachment(
                  Optional.of(AuthenticatorAttachment.PLATFORM)
                )
                .build()
            )
            .build()
        )
        val pkccoWithout = rp.startRegistration(
          StartRegistrationOptions
            .builder()
            .user(userId)
            .authenticatorSelection(
              AuthenticatorSelectionCriteria
                .builder()
                .authenticatorAttachment(
                  Optional.empty[AuthenticatorAttachment]
                )
                .build()
            )
            .build()
        )

        pkcco.getAuthenticatorSelection.get.getAuthenticatorAttachment.toScala should be(
          Some(AuthenticatorAttachment.CROSS_PLATFORM)
        )
        pkccoWith.getAuthenticatorSelection.get.getAuthenticatorAttachment.toScala should be(
          Some(AuthenticatorAttachment.PLATFORM)
        )
        pkccoWithout.getAuthenticatorSelection.get.getAuthenticatorAttachment.toScala should be(
          None
        )
      }
    }

    describe("startAssertion") {

      it("sets allowCredentials to empty if not given a username nor a user handle.") {
        forAll { credentials: Set[PublicKeyCredentialDescriptor] =>
          val rp = relyingParty(credentials = credentials, userId = userId)
          val result =
            rp.startAssertion(StartAssertionOptions.builder().build())

          result.getPublicKeyCredentialRequestOptions.getAllowCredentials.toScala shouldBe empty
        }
      }

      it("sets allowCredentials automatically if given a username.") {
        forAll { credentials: Set[PublicKeyCredentialDescriptor] =>
          val rp = relyingParty(
            credentials = credentials,
            userId = userId,
            usernameRepository = true,
          )
          val result = rp.startAssertion(
            StartAssertionOptions
              .builder()
              .username(userId.getName)
              .build()
          )

          result.getPublicKeyCredentialRequestOptions.getAllowCredentials.toScala
            .map(_.asScala.toSet) should equal(Some(credentials))
        }
      }

      it("sets allowCredentials automatically if given a user handle.") {
        forAll { credentials: Set[PublicKeyCredentialDescriptor] =>
          val rp = relyingParty(credentials = credentials, userId = userId)
          val result = rp.startAssertion(
            StartAssertionOptions
              .builder()
              .userHandle(userId.getId)
              .build()
          )

          result.getPublicKeyCredentialRequestOptions.getAllowCredentials.toScala
            .map(_.asScala.toSet) should equal(Some(credentials))
        }
      }

      it("passes username through to AssertionRequest.") {
        forAll { username: String =>
          val testCaseUserId = userId.toBuilder.name(username).build()
          val rp =
            relyingParty(userId = testCaseUserId, usernameRepository = true)
          val result = rp.startAssertion(
            StartAssertionOptions
              .builder()
              .username(testCaseUserId.getName)
              .build()
          )
          result.getUsername.asScala should equal(Some(testCaseUserId.getName))
        }
      }

      it("passes user handle through to AssertionRequest.") {
        forAll { userHandle: ByteArray =>
          val testCaseUserId = userId.toBuilder.id(userHandle).build()
          val rp = relyingParty(userId = testCaseUserId)
          val result = rp.startAssertion(
            StartAssertionOptions
              .builder()
              .userHandle(testCaseUserId.getId)
              .build()
          )
          result.getUserHandle.asScala should equal(Some(testCaseUserId.getId))
        }
      }

      it("includes transports in allowCredentials when available.") {
        forAll(
          Gen.nonEmptyContainerOf[Set, AuthenticatorTransport](
            arbitrary[AuthenticatorTransport]
          ),
          arbitrary[PublicKeyCredentialDescriptor],
          arbitrary[PublicKeyCredentialDescriptor],
          arbitrary[PublicKeyCredentialDescriptor],
        ) {
          (
              cred1Transports: Set[AuthenticatorTransport],
              cred1: PublicKeyCredentialDescriptor,
              cred2: PublicKeyCredentialDescriptor,
              cred3: PublicKeyCredentialDescriptor,
          ) =>
            val rp = relyingParty(
              credentials = Set(
                cred1.toBuilder.transports(cred1Transports.asJava).build(),
                cred2.toBuilder
                  .transports(
                    Optional.of(Set.empty[AuthenticatorTransport].asJava)
                  )
                  .build(),
                cred3.toBuilder
                  .transports(
                    Optional.empty[java.util.Set[AuthenticatorTransport]]
                  )
                  .build(),
              ),
              userId = userId,
              usernameRepository = true,
            )
            val result = rp.startAssertion(
              StartAssertionOptions
                .builder()
                .username(userId.getName)
                .build()
            )

            val requestCreds =
              result.getPublicKeyCredentialRequestOptions.getAllowCredentials.get.asScala
            requestCreds.head.getTransports.toScala should equal(
              Some(cred1Transports.asJava)
            )
            requestCreds(1).getTransports.toScala should equal(
              Some(Set.empty.asJava)
            )
            requestCreds(2).getTransports.toScala should equal(None)
        }
      }

      it("sets challenge randomly.") {
        val rp = relyingParty(userId = userId)

        val request1 =
          rp.startAssertion(StartAssertionOptions.builder().build())
        val request2 =
          rp.startAssertion(StartAssertionOptions.builder().build())

        request1.getPublicKeyCredentialRequestOptions.getChallenge should not equal request2.getPublicKeyCredentialRequestOptions.getChallenge
        request1.getPublicKeyCredentialRequestOptions.getChallenge.size should be >= 32
        request2.getPublicKeyCredentialRequestOptions.getChallenge.size should be >= 32
      }

      it("sets the appid extension if the RP instance is given an AppId.") {
        forAll { appId: AppId =>
          val rp = relyingParty(
            appId = Some(appId),
            userId = userId,
            usernameRepository = true,
          )
          val result = rp.startAssertion(
            StartAssertionOptions
              .builder()
              .username(userId.getName)
              .build()
          )

          result.getPublicKeyCredentialRequestOptions.getExtensions.getAppid.toScala should equal(
            Some(appId)
          )
        }
      }

      it("does not set the appid extension if the RP instance is not given an AppId.") {
        val rp = relyingParty(userId = userId, usernameRepository = true)
        val result = rp.startAssertion(
          StartAssertionOptions
            .builder()
            .username(userId.getName)
            .build()
        )

        result.getPublicKeyCredentialRequestOptions.getExtensions.getAppid.toScala should equal(
          None
        )
      }

      it("does not override the appid extension with an empty value if already non-null in StartAssertionOptions.") {
        forAll { requestAppId: AppId =>
          val rp = relyingParty(
            appId = None,
            userId = userId,
            usernameRepository = true,
          )
          val result = rp.startAssertion(
            StartAssertionOptions
              .builder()
              .username(userId.getName)
              .extensions(
                AssertionExtensionInputs
                  .builder()
                  .appid(requestAppId)
                  .build()
              )
              .build()
          )

          result.getPublicKeyCredentialRequestOptions.getExtensions.getAppid.toScala should equal(
            Some(requestAppId)
          )
        }
      }

      it("does not override the appid extension if already non-null in StartAssertionOptions.") {
        forAll { (requestAppId: AppId, rpAppId: AppId) =>
          whenever(requestAppId != rpAppId) {
            val rp = relyingParty(
              appId = Some(rpAppId),
              userId = userId,
              usernameRepository = true,
            )
            val result = rp.startAssertion(
              StartAssertionOptions
                .builder()
                .username(userId.getName)
                .extensions(
                  AssertionExtensionInputs
                    .builder()
                    .appid(requestAppId)
                    .build()
                )
                .build()
            )

            result.getPublicKeyCredentialRequestOptions.getExtensions.getAppid.toScala should equal(
              Some(requestAppId)
            )
          }
        }
      }

      describe("allows setting the hints") {
        val rp = relyingParty(userId = userId)

        it("to string values in the spec or not.") {
          val pkcro = rp.startAssertion(
            StartAssertionOptions
              .builder()
              .hints("hej", "security-key", "hoj", "client-device", "hybrid")
              .build()
          )
          pkcro.getPublicKeyCredentialRequestOptions.getHints.asScala should equal(
            List(
              "hej",
              PublicKeyCredentialHint.SECURITY_KEY.getValue,
              "hoj",
              PublicKeyCredentialHint.CLIENT_DEVICE.getValue,
              PublicKeyCredentialHint.HYBRID.getValue,
            )
          )
        }

        it("to PublicKeyCredentialHint values in the spec or not.") {
          val pkcro = rp.startAssertion(
            StartAssertionOptions
              .builder()
              .hints(
                PublicKeyCredentialHint.of("hej"),
                PublicKeyCredentialHint.HYBRID,
                PublicKeyCredentialHint.SECURITY_KEY,
                PublicKeyCredentialHint.of("hoj"),
                PublicKeyCredentialHint.CLIENT_DEVICE,
              )
              .build()
          )
          pkcro.getPublicKeyCredentialRequestOptions.getHints.asScala should equal(
            List(
              "hej",
              PublicKeyCredentialHint.HYBRID.getValue,
              PublicKeyCredentialHint.SECURITY_KEY.getValue,
              "hoj",
              PublicKeyCredentialHint.CLIENT_DEVICE.getValue,
            )
          )
        }

        it("or not, defaulting to the empty list.") {
          val pkcro = rp.startAssertion(StartAssertionOptions.builder().build())
          pkcro.getPublicKeyCredentialRequestOptions.getHints.asScala should equal(
            List()
          )
        }
      }

      it("allows setting the timeout to empty.") {
        val req = relyingParty(userId = userId).startAssertion(
          StartAssertionOptions
            .builder()
            .timeout(Optional.empty[java.lang.Long])
            .build()
        )
        req.getPublicKeyCredentialRequestOptions.getTimeout.toScala shouldBe empty
      }

      it("allows setting the timeout to a positive value.") {
        val rp = relyingParty(userId = userId)

        forAll(Gen.posNum[Long]) { timeout: Long =>
          val req = rp.startAssertion(
            StartAssertionOptions
              .builder()
              .timeout(timeout)
              .build()
          )

          req.getPublicKeyCredentialRequestOptions.getTimeout.toScala should equal(
            Some(timeout)
          )
        }
      }

      it("does not allow setting the timeout to zero or negative.") {
        an[IllegalArgumentException] should be thrownBy {
          StartAssertionOptions
            .builder()
            .timeout(0)
        }

        an[IllegalArgumentException] should be thrownBy {
          StartAssertionOptions
            .builder()
            .timeout(Optional.of[java.lang.Long](0L))
        }

        forAll(Gen.negNum[Long]) { timeout: Long =>
          an[IllegalArgumentException] should be thrownBy {
            StartAssertionOptions
              .builder()
              .timeout(timeout)
          }

          an[IllegalArgumentException] should be thrownBy {
            StartAssertionOptions
              .builder()
              .timeout(Optional.of[java.lang.Long](timeout))
          }
        }
      }

      it("by default does not set the uvm extension.") {
        val rp = relyingParty(userId = userId)
        val result = rp.startAssertion(
          StartAssertionOptions
            .builder()
            .build()
        )
        result.getPublicKeyCredentialRequestOptions.getExtensions.getUvm should be(
          false
        )
      }

      it("sets the uvm extension if enabled in StartRegistrationOptions.") {
        forAll { extensions: AssertionExtensionInputs =>
          val rp = relyingParty(userId = userId)
          val result = rp.startAssertion(
            StartAssertionOptions
              .builder()
              .extensions(extensions.toBuilder.uvm().build())
              .build()
          )

          result.getPublicKeyCredentialRequestOptions.getExtensions.getUvm should be(
            true
          )
        }
      }
    }
  }

  describe("StartAssertionOptions") {

    it("resets username when userHandle is set.") {
      forAll { (sao: StartAssertionOptions, userHandle: ByteArray) =>
        val result = sao.toBuilder.userHandle(userHandle).build()
        result.getUsername.toScala shouldBe empty
      }

      forAll { (sao: StartAssertionOptions, userHandle: ByteArray) =>
        val result = sao.toBuilder.userHandle(Some(userHandle).toJava).build()
        result.getUsername.toScala shouldBe empty
      }
    }

    it("resets userHandle when username is set.") {
      forAll { (sao: StartAssertionOptions, username: String) =>
        val result = sao.toBuilder.username(username).build()
        result.getUserHandle.toScala shouldBe empty
      }

      forAll { (sao: StartAssertionOptions, username: String) =>
        val result = sao.toBuilder.username(Some(username).toJava).build()
        result.getUserHandle.toScala shouldBe empty
      }
    }

    it("does not reset username when userHandle is set to empty.") {
      forAll { (sao: StartAssertionOptions, username: String) =>
        val result = sao.toBuilder
          .username(username)
          .userHandle(Optional.empty[ByteArray])
          .build()
        result.getUsername.toScala should equal(Some(username))
      }

      forAll { (sao: StartAssertionOptions, username: String) =>
        val result = sao.toBuilder
          .username(username)
          .userHandle(null: ByteArray)
          .build()
        result.getUsername.toScala should equal(Some(username))
      }
    }

    it("does not reset userHandle when username is set to empty.") {
      forAll { (sao: StartAssertionOptions, userHandle: ByteArray) =>
        val result = sao.toBuilder
          .userHandle(userHandle)
          .username(Optional.empty[String])
          .build()
        result.getUserHandle.toScala should equal(Some(userHandle))
      }

      forAll { (sao: StartAssertionOptions, userHandle: ByteArray) =>
        val result = sao.toBuilder
          .userHandle(userHandle)
          .username(null: String)
          .build()
        result.getUserHandle.toScala should equal(Some(userHandle))
      }
    }

    it("allows unsetting username.") {
      forAll { (sao: StartAssertionOptions, username: String) =>
        val preresult = sao.toBuilder.username(username).build()
        preresult.getUsername.toScala should equal(Some(username))

        val result1 =
          preresult.toBuilder.username(Optional.empty[String]).build()
        result1.getUsername.toScala shouldBe empty

        val result2 = preresult.toBuilder.username(null: String).build()
        result2.getUsername.toScala shouldBe empty
      }
    }

    it("allows unsetting userHandle.") {
      forAll { (sao: StartAssertionOptions, userHandle: ByteArray) =>
        val preresult = sao.toBuilder.userHandle(userHandle).build()
        preresult.getUserHandle.toScala should equal(Some(userHandle))

        val result1 =
          preresult.toBuilder.userHandle(Optional.empty[ByteArray]).build()
        result1.getUserHandle.toScala shouldBe empty

        val result2 = preresult.toBuilder.userHandle(null: ByteArray).build()
        result2.getUserHandle.toScala shouldBe empty
      }
    }
  }

  describe("AssertionRequest") {

    it("resets username when userHandle is set.") {
      forAll { (ar: AssertionRequest, userHandle: ByteArray) =>
        val result = ar.toBuilder.userHandle(userHandle).build()
        result.getUsername.asScala shouldBe empty
      }

      forAll { (ar: AssertionRequest, userHandle: ByteArray) =>
        val result = ar.toBuilder.userHandle(Some(userHandle).asJava).build()
        result.getUsername.asScala shouldBe empty
      }
    }

    it("resets userHandle when username is set.") {
      forAll { (ar: AssertionRequest, username: String) =>
        val result = ar.toBuilder.username(username).build()
        result.getUserHandle.asScala shouldBe empty
      }

      forAll { (ar: AssertionRequest, username: String) =>
        val result = ar.toBuilder.username(Some(username).asJava).build()
        result.getUserHandle.asScala shouldBe empty
      }
    }

    it("does not reset username when userHandle is set to empty.") {
      forAll { (ar: AssertionRequest, username: String) =>
        val result = ar.toBuilder
          .username(username)
          .userHandle(Optional.empty[ByteArray])
          .build()
        result.getUsername.asScala should equal(Some(username))
      }

      forAll { (ar: AssertionRequest, username: String) =>
        val result = ar.toBuilder
          .username(username)
          .userHandle(null: ByteArray)
          .build()
        result.getUsername.asScala should equal(Some(username))
      }
    }

    it("does not reset userHandle when username is set to empty.") {
      forAll { (ar: AssertionRequest, userHandle: ByteArray) =>
        val result = ar.toBuilder
          .userHandle(userHandle)
          .username(Optional.empty[String])
          .build()
        result.getUserHandle.asScala should equal(Some(userHandle))
      }

      forAll { (ar: AssertionRequest, userHandle: ByteArray) =>
        val result = ar.toBuilder
          .userHandle(userHandle)
          .username(null: String)
          .build()
        result.getUserHandle.asScala should equal(Some(userHandle))
      }
    }

    it("allows unsetting username.") {
      forAll { (ar: AssertionRequest, username: String) =>
        val preresult = ar.toBuilder.username(username).build()
        preresult.getUsername.asScala should equal(Some(username))

        val result1 =
          preresult.toBuilder.username(Optional.empty[String]).build()
        result1.getUsername.asScala shouldBe empty

        val result2 = preresult.toBuilder.username(null: String).build()
        result2.getUsername.asScala shouldBe empty
      }
    }

    it("allows unsetting userHandle.") {
      forAll { (ar: AssertionRequest, userHandle: ByteArray) =>
        val preresult = ar.toBuilder.userHandle(userHandle).build()
        preresult.getUserHandle.asScala should equal(Some(userHandle))

        val result1 =
          preresult.toBuilder.userHandle(Optional.empty[ByteArray]).build()
        result1.getUserHandle.asScala shouldBe empty

        val result2 = preresult.toBuilder.userHandle(null: ByteArray).build()
        result2.getUserHandle.asScala shouldBe empty
      }
    }
  }

}
