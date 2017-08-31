package com.yubico.webauthn.util

import org.junit.runner.RunWith
import org.scalatest.Matchers
import org.scalatest.FunSpec
import org.scalatest.junit.JUnitRunner


@RunWith(classOf[JUnitRunner])
class BinaryUtilSpec extends FunSpec with Matchers {

  describe("BinaryUtil.getUint8") {

    it("returns 0 for 0x00.") {
      BinaryUtil.getUint8(BinaryUtil.fromHex("00").get).get should equal (0)
    }

    it("returns 127 for 0x7f.") {
      BinaryUtil.getUint8(BinaryUtil.fromHex("7f").get).get should equal (127)
    }

    it("returns 128 for 0x80.") {
      BinaryUtil.getUint8(BinaryUtil.fromHex("80").get).get should equal (128)
    }

    it("returns 255 for 0xff.") {
      BinaryUtil.getUint8(BinaryUtil.fromHex("ff").get).get should equal (255)
    }

  }

  describe("BinaryUtil.getUint16") {

    it("returns 0 for 0x0000.") {
      BinaryUtil.getUint16(BinaryUtil.fromHex("0000").get).get should equal (0)
    }

    it("returns 256 for 0x0100.") {
      BinaryUtil.getUint16(BinaryUtil.fromHex("0100").get).get should equal (256)
    }

    it("returns 65535 for 0xffff.") {
      BinaryUtil.getUint16(BinaryUtil.fromHex("ffff").get).get should equal (65535)
    }

  }

  describe("BinaryUtil.getUint32") {

    it("returns 0 for 0x0000.") {
      BinaryUtil.getUint32(BinaryUtil.fromHex("00000000").get).get should equal (0)
    }

    it("returns 65536 for 0x00010000.") {
      BinaryUtil.getUint32(BinaryUtil.fromHex("00010000").get).get should equal (65536)
    }

    it("returns 4294967295 for 0xffffffff.") {
      BinaryUtil.getUint32(BinaryUtil.fromHex("ffffffff").get).get should equal (4294967295L)
    }

  }

}
