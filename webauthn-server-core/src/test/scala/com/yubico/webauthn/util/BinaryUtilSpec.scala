package com.yubico.webauthn.util

import org.junit.runner.RunWith
import org.scalatest.Matchers
import org.scalatest.FunSpec
import org.scalatest.junit.JUnitRunner


@RunWith(classOf[JUnitRunner])
class BinaryUtilSpec extends FunSpec with Matchers {

  describe("BinaryUtil.fromHex") {

    it("decodes 00 to [0].") {
      BinaryUtil.fromHex("00").get should equal (Array[Byte](0))
    }

    it("decodes 2a to [42].") {
      BinaryUtil.fromHex("2a").get should equal (Array[Byte](42))
    }

    it("decodes 000101020305080d15 to [0, 1, 1, 2, 3, 5, 8, 13, 21].") {
      BinaryUtil.fromHex("000101020305080d15").get should equal (Array[Byte](0, 1, 1, 2, 3, 5, 8, 13, 21))
    }
  }

  describe("BinaryUtil.toHex") {
    it("encodes [0, 1, 1, 2, 3, 5, 8, 13, 21] to 000101020305080d15.") {
      BinaryUtil.toHex(Array[Byte](0, 1, 1, 2, 3, 5, 8, 13, 21)) should equal ("000101020305080d15")
    }
  }

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
