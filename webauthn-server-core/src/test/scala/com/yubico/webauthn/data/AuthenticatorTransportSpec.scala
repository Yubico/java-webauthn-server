// Copyright (c) 2019, Yubico AB
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

package com.yubico.webauthn.data

import com.yubico.webauthn.attestation.Transport
import org.junit.runner.RunWith
import org.scalatest.FunSpec
import org.scalatest.Matchers
import org.scalatestplus.junit.JUnitRunner
import org.scalatestplus.scalacheck.ScalaCheckDrivenPropertyChecks

@RunWith(classOf[JUnitRunner])
class AuthenticatorTransportSpec
    extends FunSpec
    with Matchers
    with ScalaCheckDrivenPropertyChecks {

  describe("The AuthenticatorTransport type") {

    describe("has the constant") {
      it("USB.") {
        AuthenticatorTransport.USB.getId should equal("usb")
      }
      it("NFC.") {
        AuthenticatorTransport.NFC.getId should equal("nfc")
      }
      it("BLE.") {
        AuthenticatorTransport.BLE.getId should equal("ble")
      }
      it("INTERNAL.") {
        AuthenticatorTransport.INTERNAL.getId should equal("internal")
      }
    }

    it("has a values() function.") {
      AuthenticatorTransport.values().length should equal(4)
      AuthenticatorTransport.values() should not be theSameInstanceAs(
        AuthenticatorTransport.values()
      )
    }

    it("has a valueOf(name) function mimicking that of an enum type.") {
      AuthenticatorTransport.valueOf(
        "USB"
      ) should be theSameInstanceAs AuthenticatorTransport.USB
      AuthenticatorTransport.valueOf(
        "NFC"
      ) should be theSameInstanceAs AuthenticatorTransport.NFC
      AuthenticatorTransport.valueOf(
        "BLE"
      ) should be theSameInstanceAs AuthenticatorTransport.BLE
      AuthenticatorTransport.valueOf(
        "INTERNAL"
      ) should be theSameInstanceAs AuthenticatorTransport.INTERNAL
      an[IllegalArgumentException] should be thrownBy {
        AuthenticatorTransport.valueOf("foo")
      }
    }

    it("can contain any value.") {
      forAll { transport: String =>
        AuthenticatorTransport.of(transport).getId should equal(transport)
      }
    }

    it("has an of(id) function which returns the corresponding constant instance if applicable, and a new instance otherwise.") {
      for { constant <- AuthenticatorTransport.values() } {
        AuthenticatorTransport.of(constant.getId) should equal(constant)
        AuthenticatorTransport.of(
          constant.getId
        ) should be theSameInstanceAs constant
        AuthenticatorTransport.of(
          constant.getId.toUpperCase
        ) should not equal constant
      }
    }

    it("has a fromU2fTransport(transport) function that can convert from Transport.") {
      AuthenticatorTransport.fromU2fTransport(
        Transport.BT_CLASSIC
      ) should be theSameInstanceAs AuthenticatorTransport.BLE
      AuthenticatorTransport.fromU2fTransport(
        Transport.BLE
      ) should be theSameInstanceAs AuthenticatorTransport.BLE
      AuthenticatorTransport.fromU2fTransport(
        Transport.USB
      ) should be theSameInstanceAs AuthenticatorTransport.USB
      AuthenticatorTransport.fromU2fTransport(
        Transport.LIGHTNING
      ) should be theSameInstanceAs AuthenticatorTransport.USB
      AuthenticatorTransport.fromU2fTransport(
        Transport.NFC
      ) should be theSameInstanceAs AuthenticatorTransport.NFC
    }
  }
}
