package com.yubico.webauthn.data.impl

import com.yubico.webauthn.util.BinaryUtil
import org.junit.runner.RunWith
import org.scalatest.Matchers
import org.scalatest.FunSpec
import org.scalatest.junit.JUnitRunner


@RunWith(classOf[JUnitRunner])
class AuthenticatorDataSpec extends FunSpec with Matchers {

  describe("AuthenticatorData") {

    val bytes = BinaryUtil.fromHex("49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d97630100000539").get
    val authData = AuthenticatorData(bytes)

    it("can parse the RP ID hash from the raw bytes.") {
      BinaryUtil.toHex(authData.rpIdHash) should equal ("49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d9763")
    }

    it("can parse the flags from the raw bytes.") {
      authData.flags.UP should be (true)
      authData.flags.UV should be (false)
      authData.flags.AT should be (false)
      authData.flags.ED should be (false)
    }

    it("can parse the signature counter raw bytes.") {
      authData.signatureCounter should equal (1337)

      val evilBytes = BinaryUtil.fromHex("49960de5880e8c687434170f6476605b8fe4aeb9a28632c7995cf3ba831d976301ffffffff").get
      AuthenticatorData(evilBytes).signatureCounter should equal (0xffffffffL)
      AuthenticatorData(evilBytes).signatureCounter should be > Int.MaxValue.toLong
    }

  }

}
