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

import com.yubico.webauthn.data.ByteArray
import com.yubico.webauthn.data.Generators.arbitraryByteArray
import com.yubico.webauthn.test.Util
import org.junit.runner.RunWith
import org.scalacheck.Arbitrary
import org.scalacheck.Gen
import org.scalatest.funspec.AnyFunSpec
import org.scalatest.matchers.should.Matchers
import org.scalatestplus.junit.JUnitRunner
import org.scalatestplus.scalacheck.ScalaCheckDrivenPropertyChecks

import java.security.interfaces.ECPublicKey
import scala.util.Try

@RunWith(classOf[JUnitRunner])
class WebAuthnCodecsSpec
    extends AnyFunSpec
    with Matchers
    with ScalaCheckDrivenPropertyChecks
    with TestWithEachProvider {

  implicit def arbitraryEcPublicKey: Arbitrary[ECPublicKey] =
    Arbitrary(
      for {
        ySign: Byte <- Gen.oneOf(0x02: Byte, 0x03: Byte)
        rawBytes <- Gen.listOfN[Byte](32, Arbitrary.arbitrary[Byte])
        key = Try(
          Util
            .decodePublicKey(new ByteArray((ySign +: rawBytes).toArray))
            .asInstanceOf[ECPublicKey]
        )
        if key.isSuccess
      } yield key.get
    )

  testWithEachProvider { it =>
    describe("The ecPublicKeyToRaw method") {

      it("outputs the correct x and y values") {
        forAll(minSuccessful(500)) { pubkey: ECPublicKey =>
          val rawkey: Array[Byte] =
            WebAuthnCodecs.ecPublicKeyToRaw(pubkey).getBytes

          rawkey.length should equal(65)
          rawkey(0) should equal(0x04: Byte)

          val x = rawkey.slice(1, 33)
          val y = rawkey.slice(33, 65)

          val expectedX = pubkey.getW.getAffineX.toByteArray.toVector
          val expectedY = pubkey.getW.getAffineY.toByteArray.toVector

          x.dropWhile(_ == (0: Byte)) should equal(
            expectedX.dropWhile(_ == (0: Byte))
          )
          y.dropWhile(_ == (0: Byte)) should equal(
            expectedY.dropWhile(_ == (0: Byte))
          )
        }
      }

    }

    describe("The rawEcKeyToCose method") {

      it("outputs a value that can be imported by importCoseP256PublicKey") {
        forAll { originalPubkey: ECPublicKey =>
          val rawKey = WebAuthnCodecs.ecPublicKeyToRaw(originalPubkey)

          val coseKey = WebAuthnCodecs.rawEcKeyToCose(rawKey)

          val importedPubkey: ECPublicKey = WebAuthnCodecs
            .importCosePublicKey(coseKey)
            .asInstanceOf[ECPublicKey]
          val rawImportedPubkey =
            WebAuthnCodecs.ecPublicKeyToRaw(importedPubkey)

          rawImportedPubkey should equal(rawKey)
        }
      }

    }

    describe("The ecPublicKeyToCose method") {

      it("outputs a value that can be imported by importCoseP256PublicKey") {
        forAll { originalPubkey: ECPublicKey =>
          val rawKey = WebAuthnCodecs.ecPublicKeyToRaw(originalPubkey)

          val coseKey = WebAuthnTestCodecs.ecPublicKeyToCose(originalPubkey)

          val importedPubkey: ECPublicKey = WebAuthnCodecs
            .importCosePublicKey(coseKey)
            .asInstanceOf[ECPublicKey]
          val rawImportedPubkey =
            WebAuthnCodecs.ecPublicKeyToRaw(importedPubkey)

          rawImportedPubkey should equal(rawKey)
        }
      }

    }

    describe("DER parsing and encoding:") {
      it("encodeDerLength and parseDerLength are each other's inverse.") {
        forAll(Gen.chooseNum(0, Int.MaxValue), arbitraryByteArray.arbitrary) {
          (len: Int, prefix: ByteArray) =>
            val encoded = WebAuthnCodecs.encodeDerLength(len)
            val decoded = WebAuthnCodecs.parseDerLength(encoded.getBytes, 0)
            val decodedWithPrefix = WebAuthnCodecs.parseDerLength(
              prefix.concat(encoded).getBytes,
              prefix.size,
            )

            decoded.result should equal(len)
            decoded.nextOffset should equal(encoded.size)
            decodedWithPrefix.result should equal(len)
            decodedWithPrefix.nextOffset should equal(
              prefix.size + encoded.size
            )

            val recoded = WebAuthnCodecs.encodeDerLength(decoded.result)
            recoded should equal(encoded)
        }
      }

      it("parseDerLength tolerates unnecessarily long encodings.") {
        WebAuthnCodecs
          .parseDerLength(Array(0x81, 0).map(_.toByte), 0)
          .result should equal(0)
        WebAuthnCodecs
          .parseDerLength(Array(0x82, 0, 0).map(_.toByte), 0)
          .result should equal(0)
        WebAuthnCodecs
          .parseDerLength(Array(0x83, 0, 0, 0).map(_.toByte), 0)
          .result should equal(0)
        WebAuthnCodecs
          .parseDerLength(Array(0x84, 0, 0, 0, 0).map(_.toByte), 0)
          .result should equal(0)
        WebAuthnCodecs
          .parseDerLength(Array(0x81, 7).map(_.toByte), 0)
          .result should equal(7)
        WebAuthnCodecs
          .parseDerLength(Array(0x82, 0, 7).map(_.toByte), 0)
          .result should equal(7)
        WebAuthnCodecs
          .parseDerLength(Array(0x83, 0, 0, 7).map(_.toByte), 0)
          .result should equal(7)
        WebAuthnCodecs
          .parseDerLength(Array(0x84, 0, 0, 4, 2).map(_.toByte), 0)
          .result should equal(1026)
        WebAuthnCodecs
          .parseDerLength(Array(0x84, 0, 1, 33, 7).map(_.toByte), 0)
          .result should equal(73991)
      }

      it("encodeDerSequence and parseDerSequenceEnd are (almost) each other's inverse.") {
        forAll { (data: Array[ByteArray], prefix: ByteArray) =>
          val encoded = WebAuthnCodecs.encodeDerSequence(data: _*)
          val decoded = WebAuthnCodecs.parseDerSequence(encoded.getBytes, 0)
          val encodedWithPrefix = prefix.concat(encoded)
          val decodedWithPrefix = WebAuthnCodecs.parseDerSequence(
            encodedWithPrefix.getBytes,
            prefix.size,
          )

          val expectedContent: ByteArray =
            data.fold(new ByteArray(Array.empty))((a, b) => a.concat(b))
          decoded.result should equal(expectedContent)
          decodedWithPrefix.result should equal(expectedContent)
          decoded.nextOffset should equal(encoded.size)
          decodedWithPrefix.nextOffset should equal(prefix.size + encoded.size)
        }
      }

      it("parseDerSequence fails if the first byte is not 0x30.") {
        forAll { (tag: Byte, data: Array[ByteArray]) =>
          whenever(tag != 0x30) {
            val encoded = WebAuthnCodecs.encodeDerSequence(data: _*)
            an[IllegalArgumentException] shouldBe thrownBy {
              WebAuthnCodecs.parseDerSequence(
                encoded.getBytes.updated(0, tag),
                0,
              )
            }
          }
        }
      }

      it("parseDerSequence fails on empty input.") {
        an[IllegalArgumentException] shouldBe thrownBy {
          WebAuthnCodecs.parseDerSequence(Array.empty, 0)
        }
        forAll { data: Array[Byte] =>
          an[IllegalArgumentException] shouldBe thrownBy {
            WebAuthnCodecs.parseDerSequence(data, data.length)
          }
        }
      }
    }
  }
}
