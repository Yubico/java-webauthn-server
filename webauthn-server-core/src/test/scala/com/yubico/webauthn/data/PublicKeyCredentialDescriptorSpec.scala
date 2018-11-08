package com.yubico.webauthn.data

import org.scalatest.Matchers
import org.scalatest.FunSpec
import org.scalatest.prop.GeneratorDrivenPropertyChecks
import Generators._


class PublicKeyCredentialDescriptorSpec extends FunSpec with Matchers with GeneratorDrivenPropertyChecks {

  describe("PublicKeyCredentialDescriptor") {

    describe("has a compareTo method") {

      describe("which is consistent with") {

        implicit val generatorDrivenConfig = PropertyCheckConfig(minSuccessful = 300)

        it("equals.") {
          forAll { (a: PublicKeyCredentialDescriptor, b: PublicKeyCredentialDescriptor) =>
            val comparison = a.compareTo(b)

            if (a == b) {
              comparison should equal (0)
            } else {
              comparison should not equal 0
            }
          }
        }

        it("hashCode.") {
          forAll { (a: PublicKeyCredentialDescriptor, b: PublicKeyCredentialDescriptor) =>
            if (a.compareTo(b) == 0) {
              a.hashCode() should equal (b.hashCode())
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
