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

package com.yubico.webauthn.data

import com.yubico.webauthn.data.Generators._
import org.scalatest.FunSpec
import org.scalatest.Matchers
import org.scalatestplus.scalacheck.ScalaCheckDrivenPropertyChecks

class PublicKeyCredentialDescriptorSpec
    extends FunSpec
    with Matchers
    with ScalaCheckDrivenPropertyChecks {

  describe("PublicKeyCredentialDescriptor") {

    describe("has a compareTo method") {

      describe("which is consistent with") {

        implicit val generatorDrivenConfig =
          PropertyCheckConfiguration(minSuccessful = 300)

        it("equals.") {
          forAll {
            (
                a: PublicKeyCredentialDescriptor,
                b: PublicKeyCredentialDescriptor,
            ) =>
              val comparison = a.compareTo(b)

              if (a == b) {
                comparison should equal(0)
              } else {
                comparison should not equal 0
              }
          }
        }

        it("hashCode.") {
          forAll {
            (
                a: PublicKeyCredentialDescriptor,
                b: PublicKeyCredentialDescriptor,
            ) =>
              if (a.compareTo(b) == 0) {
                a.hashCode() should equal(b.hashCode())
              }

              if (a.hashCode() != b.hashCode()) {
                a.compareTo(b) should not be 0
              }
          }
        }

      }

    }

  }

}
