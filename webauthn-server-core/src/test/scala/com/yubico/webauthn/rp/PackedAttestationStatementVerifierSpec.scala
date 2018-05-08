package com.yubico.webauthn.rp

import com.yubico.webauthn.impl.PackedAttestationStatementVerifier
import com.yubico.webauthn.test.Util
import com.yubico.webauthn.util.BinaryUtil
import org.scalatest.FunSpec
import org.scalatest.Matchers

import scala.util.Success


class PackedAttestationStatementVerifierSpec extends FunSpec with Matchers {

  val verifier = PackedAttestationStatementVerifier

  describe("The X.509 certificate requirements") {

    it("pass Klas's attestation certificate.") {

      val cert = Util.importCertFromPem(getClass.getResourceAsStream("klas-cert.pem"))

      val result = verifier._verifyX5cRequirements(cert, BinaryUtil.fromHex("F8A011F38C0A4D15800617111F9EDC7D").get)

      result shouldBe a [Success[_]]
      result.get should be (true)
    }

  }

}
