package com.yubico.webauthn.util

import java.security.KeyPairGenerator
import java.security.SecureRandom
import java.security.interfaces.ECPublicKey

import com.yubico.u2f.crypto.BouncyCastleCrypto
import org.bouncycastle.jce.ECNamedCurveTable
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.junit.runner.RunWith
import org.scalacheck.Arbitrary
import org.scalacheck.Gen
import org.scalatest.Matchers
import org.scalatest.FunSpec
import org.scalatest.junit.JUnitRunner
import org.scalatest.prop.GeneratorDrivenPropertyChecks

import scala.util.Try


@RunWith(classOf[JUnitRunner])
class WebAuthnCodecsSpec  extends FunSpec with Matchers with GeneratorDrivenPropertyChecks {

  private val javaCryptoProvider: java.security.Provider = new BouncyCastleProvider

  implicit def arbitraryEcPublicKey: Arbitrary[ECPublicKey] = Arbitrary(
    for {
      ySign: Byte <- Gen.oneOf(0x02: Byte, 0x03: Byte)
      rawBytes: Seq[Byte] <- Gen.listOfN[Byte](32, Arbitrary.arbitrary[Byte])
      key = Try(new BouncyCastleCrypto().decodePublicKey((ySign +: rawBytes).toArray).asInstanceOf[ECPublicKey])
      if key.isSuccess
    } yield key.get
  )

  describe("The ecPublicKeyToRaw method") {

    it("outputs the correct x and y values") {
      forAll { pubkey: ECPublicKey =>
        val rawkey = WebAuthnCodecs.ecPublicKeyToRaw(pubkey)

        rawkey.length should equal (65)
        rawkey(0) should equal (0x04: Byte)

        val x = rawkey.slice(1, 33)
        val y = rawkey.slice(33, 65)

        val expectedX = pubkey.getW.getAffineX.toByteArray.toVector
        val expectedY = pubkey.getW.getAffineY.toByteArray.toVector

        x should equal (if (expectedX.length == 33 && expectedX(0) == 0) expectedX.tail else expectedX)
        y should equal (if (expectedY.length == 33 && expectedY(0) == 0) expectedY.tail else expectedY)
      }
    }

  }

  describe("The rawEcdaKeyToCose method") {

    it("outputs a value that can be imported by importCoseP256PublicKey") {
      forAll { originalPubkey: ECPublicKey =>
        val rawKey = WebAuthnCodecs.ecPublicKeyToRaw(originalPubkey)

        val coseKey = WebAuthnCodecs.rawEcdaKeyToCose(rawKey)

        val importedPubkey: ECPublicKey = WebAuthnCodecs.importCoseP256PublicKey(coseKey)
        val rawImportedPubkey = WebAuthnCodecs.ecPublicKeyToRaw(importedPubkey)

        rawImportedPubkey should equal (rawKey)
      }
    }

  }

  describe("The ecPublicKeyToCose method") {

    it("outputs a value that can be imported by importCoseP256PublicKey") {
      forAll { originalPubkey: ECPublicKey =>
        val rawKey = WebAuthnCodecs.ecPublicKeyToRaw(originalPubkey)

        val coseKey = WebAuthnCodecs.ecPublicKeyToCose(originalPubkey)

        val importedPubkey: ECPublicKey = WebAuthnCodecs.importCoseP256PublicKey(coseKey)
        val rawImportedPubkey = WebAuthnCodecs.ecPublicKeyToRaw(importedPubkey)

        rawImportedPubkey should equal (rawKey)
      }
    }

  }

}
