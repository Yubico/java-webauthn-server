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

package com.yubico.internal.util

import org.junit.runner.RunWith
import org.scalacheck.Arbitrary
import org.scalacheck.Gen
import org.scalatest.funspec.AnyFunSpec
import org.scalatest.matchers.should.Matchers
import org.scalatestplus.junit.JUnitRunner
import org.scalatestplus.scalacheck.ScalaCheckDrivenPropertyChecks

@RunWith(classOf[JUnitRunner])
class BinaryUtilSpec
    extends AnyFunSpec
    with Matchers
    with ScalaCheckDrivenPropertyChecks {

  describe("BinaryUtil.fromHex") {

    it("decodes 00 to [0].") {
      BinaryUtil.fromHex("00").toVector should equal(Array[Byte](0))
    }

    it("decodes 2a to [42].") {
      BinaryUtil.fromHex("2a").toVector should equal(Array[Byte](42))
    }

    it("decodes 000101020305080d15 to [0, 1, 1, 2, 3, 5, 8, 13, 21].") {
      BinaryUtil.fromHex("000101020305080d15").toVector should equal(
        Array[Byte](0, 1, 1, 2, 3, 5, 8, 13, 21)
      )
    }
  }

  describe("BinaryUtil.toHex") {
    it("encodes [0, 1, 1, 2, 3, 5, 8, 13, 21] to 000101020305080d15.") {
      BinaryUtil.toHex(Array[Byte](0, 1, 1, 2, 3, 5, 8, 13, 21)) should equal(
        "000101020305080d15"
      )
    }
  }

  describe("BinaryUtil.getUint8") {

    it("returns 0 for 0x00.") {
      BinaryUtil.getUint8(BinaryUtil.fromHex("00").head) should equal(0)
    }

    it("returns 127 for 0x7f.") {
      BinaryUtil.getUint8(BinaryUtil.fromHex("7f").head) should equal(127)
    }

    it("returns 128 for 0x80.") {
      BinaryUtil.getUint8(BinaryUtil.fromHex("80").head) should equal(128)
    }

    it("returns 255 for 0xff.") {
      BinaryUtil.getUint8(BinaryUtil.fromHex("ff").head) should equal(255)
    }

  }

  describe("BinaryUtil.getUint16") {

    it("returns 0 for 0x0000.") {
      BinaryUtil.getUint16(BinaryUtil.fromHex("0000")) should equal(0)
    }

    it("returns 256 for 0x0100.") {
      BinaryUtil.getUint16(BinaryUtil.fromHex("0100")) should equal(256)
    }

    it("returns 65535 for 0xffff.") {
      BinaryUtil.getUint16(BinaryUtil.fromHex("ffff")) should equal(65535)
    }

  }

  describe("BinaryUtil.getUint32") {

    it("returns 0 for 0x0000.") {
      BinaryUtil.getUint32(BinaryUtil.fromHex("00000000")) should equal(0)
    }

    it("returns 65536 for 0x00010000.") {
      BinaryUtil.getUint32(BinaryUtil.fromHex("00010000")) should equal(65536)
    }

    it("returns 4294967295 for 0xffffffff.") {
      BinaryUtil.getUint32(BinaryUtil.fromHex("ffffffff")) should equal(
        4294967295L
      )
    }

  }

  describe("BinaryUtil.encodeUint16") {

    it("returns 0x0000 for 0.") {
      BinaryUtil.encodeUint16(0) should equal(Array(0, 0))
    }

    it("returns 0xEFFF for 32767.") {
      BinaryUtil.getUint32(BinaryUtil.fromHex("00010000")) should equal(65536)
    }

    it("returns a value that getUint16 can reverse.") {
      forAll(Gen.choose(0, 65536)) { i =>
        BinaryUtil.getUint16(BinaryUtil.encodeUint16(i)) == i
      }
    }

    it("rejects negative inputs.") {
      forAll(Gen.choose(Int.MinValue, -1)) { i =>
        an[IllegalArgumentException] shouldBe thrownBy(
          BinaryUtil.encodeUint16(i)
        )
      }
    }

    it("rejects too large inputs.") {
      forAll(Gen.choose(65536, Int.MaxValue)) { i =>
        an[IllegalArgumentException] shouldBe thrownBy(
          BinaryUtil.encodeUint16(i)
        )
      }
    }
  }

  describe("DER parsing and encoding:") {
    it("encodeDerLength and parseDerLength are each other's inverse.") {
      forAll(
        Gen.chooseNum(0, Int.MaxValue),
        Arbitrary.arbitrary[Array[Byte]],
      ) { (len: Int, prefix: Array[Byte]) =>
        val encoded = BinaryUtil.encodeDerLength(len)
        val decoded = BinaryUtil.parseDerLength(encoded, 0)
        val decodedWithPrefix = BinaryUtil.parseDerLength(
          BinaryUtil.concat(prefix, encoded),
          prefix.length,
        )

        decoded.result should equal(len)
        decoded.nextOffset should equal(encoded.length)
        decodedWithPrefix.result should equal(len)
        decodedWithPrefix.nextOffset should equal(
          prefix.length + encoded.length
        )

        val recoded = BinaryUtil.encodeDerLength(decoded.result)
        recoded should equal(encoded)
      }
    }

    it("parseDerLength tolerates unnecessarily long encodings.") {
      BinaryUtil
        .parseDerLength(Array(0x81, 0).map(_.toByte), 0)
        .result should equal(0)
      BinaryUtil
        .parseDerLength(Array(0x82, 0, 0).map(_.toByte), 0)
        .result should equal(0)
      BinaryUtil
        .parseDerLength(Array(0x83, 0, 0, 0).map(_.toByte), 0)
        .result should equal(0)
      BinaryUtil
        .parseDerLength(Array(0x84, 0, 0, 0, 0).map(_.toByte), 0)
        .result should equal(0)
      BinaryUtil
        .parseDerLength(Array(0x81, 7).map(_.toByte), 0)
        .result should equal(7)
      BinaryUtil
        .parseDerLength(Array(0x82, 0, 7).map(_.toByte), 0)
        .result should equal(7)
      BinaryUtil
        .parseDerLength(Array(0x83, 0, 0, 7).map(_.toByte), 0)
        .result should equal(7)
      BinaryUtil
        .parseDerLength(Array(0x84, 0, 0, 4, 2).map(_.toByte), 0)
        .result should equal(1026)
      BinaryUtil
        .parseDerLength(Array(0x84, 0, 1, 33, 7).map(_.toByte), 0)
        .result should equal(73991)
    }

    it("encodeDerSequence and parseDerSequenceEnd are (almost) each other's inverse.") {
      forAll { (data: Array[Array[Byte]], prefix: Array[Byte]) =>
        val encoded = BinaryUtil.encodeDerSequence(data: _*)
        val decoded = BinaryUtil.parseDerSequence(encoded, 0)
        val encodedWithPrefix = BinaryUtil.concat(prefix, encoded)
        val decodedWithPrefix = BinaryUtil.parseDerSequence(
          encodedWithPrefix,
          prefix.length,
        )

        val expectedContent: Array[Byte] = BinaryUtil.concat(data: _*)
        decoded.result should equal(expectedContent)
        decodedWithPrefix.result should equal(expectedContent)
        decoded.nextOffset should equal(encoded.length)
        decodedWithPrefix.nextOffset should equal(
          prefix.length + encoded.length
        )
      }
    }

    it("parseDerSequence fails if the first byte is not 0x30.") {
      forAll { (tag: Byte, data: Array[Array[Byte]]) =>
        whenever(tag != 0x30) {
          val encoded = BinaryUtil.encodeDerSequence(data: _*)
          an[IllegalArgumentException] shouldBe thrownBy {
            BinaryUtil.parseDerSequence(
              encoded.updated(0, tag),
              0,
            )
          }
        }
      }
    }

    it("parseDerSequence fails on empty input.") {
      an[IllegalArgumentException] shouldBe thrownBy {
        BinaryUtil.parseDerSequence(Array.empty, 0)
      }
      forAll { data: Array[Byte] =>
        an[IllegalArgumentException] shouldBe thrownBy {
          BinaryUtil.parseDerSequence(data, data.length)
        }
      }
    }
  }

}
