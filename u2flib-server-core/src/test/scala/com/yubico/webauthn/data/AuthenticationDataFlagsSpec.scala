package com.yubico.webauthn.data

import com.yubico.webauthn.util.BinaryUtil
import org.junit.runner.RunWith
import org.scalatest.FunSpec
import org.scalatest.Matchers
import org.scalatest.junit.JUnitRunner


@RunWith(classOf[JUnitRunner])
class AuthenticationDataFlagsSpec extends FunSpec with Matchers {

  describe("AuthenticationDataFlags") {

    describe("decodes") {
      def decode(hex: HexString) = AuthenticationDataFlags(BinaryUtil.fromHex(hex).get(0))

      it("0x01 to UP.") {
        val flags = decode("01")
        flags.UP should be (true)
        flags.UV should be (false)
        flags.AT should be (false)
        flags.ED should be (false)
      }

      it("0x04 to UV.") {
        val flags = decode("04")
        flags.UP should be (false)
        flags.UV should be (true)
        flags.AT should be (false)
        flags.ED should be (false)
      }

      it("0x40 to AT.") {
        val flags = decode("40")
        flags.UP should be (false)
        flags.UV should be (false)
        flags.AT should be (true)
        flags.ED should be (false)
      }

      it("0x80 to ED.") {
        val flags = decode("80")
        flags.UP should be (false)
        flags.UV should be (false)
        flags.AT should be (false)
        flags.ED should be (true)
      }

    }

  }

}
