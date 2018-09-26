package com.yubico.webauthn

import java.util.Optional

import com.yubico.internal.util.scala.JavaConverters._
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor
import com.yubico.webauthn.data.ByteArray
import com.yubico.webauthn.data.UserIdentity
import com.yubico.webauthn.data.RelyingPartyIdentity
import com.yubico.webauthn.data.PublicKeyCredentialParameters
import com.yubico.webauthn.data.Generators._
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

  def relyingParty(credentials: Set[PublicKeyCredentialDescriptor]): RelyingParty = RelyingParty.builder()
    .rp(rpId)
    .preferredPubkeyParams(List(PublicKeyCredentialParameters.ES256).asJava)
    .credentialRepository(credRepo(credentials))
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
        val rp = relyingParty(credentials)
        val result = rp.startRegistration(StartRegistrationOptions.builder()
          .user(userId)
          .build()
        )

        result.getExcludeCredentials.asScala.map(_.asScala) should equal (Some(credentials))
      }
    }

  }

  describe("RelyingParty.startAssertion") {

    it("sets allowCredentials to empty if not given a username.") {
      forAll { credentials: Set[PublicKeyCredentialDescriptor] =>
        val rp = relyingParty(credentials)
        val result = rp.startAssertion(StartAssertionOptions.builder().build())

        result.getPublicKeyCredentialRequestOptions.getAllowCredentials.asScala shouldBe empty
      }
    }

    it("sets allowCredentials automatically if given a username.") {
      forAll { credentials: Set[PublicKeyCredentialDescriptor] =>
        val rp = relyingParty(credentials)
        val result = rp.startAssertion(StartAssertionOptions.builder()
          .username(Some(userId.getName).asJava)
          .build()
        )

        result.getPublicKeyCredentialRequestOptions.getAllowCredentials.asScala.map(_.asScala) should equal (Some(credentials))
      }
    }

  }

}
