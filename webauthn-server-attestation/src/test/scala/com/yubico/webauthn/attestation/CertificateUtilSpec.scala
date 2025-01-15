package com.yubico.webauthn.attestation

import com.yubico.webauthn.TestAuthenticator
import com.yubico.webauthn.data.ByteArray
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.x500.X500Name
import org.junit.runner.RunWith
import org.scalatest.funspec.AnyFunSpec
import org.scalatest.matchers.should.Matchers
import org.scalatestplus.junit.JUnitRunner

import java.security.cert.X509Certificate

@RunWith(classOf[JUnitRunner])
class CertificateUtilSpec extends AnyFunSpec with Matchers {
  describe("parseFidoSerNumExtension") {
    val idFidoGenCeSernum = "1.3.6.1.4.1.45724.1.1.2"
    it("should correctly parse the serial number from a valid certificate with the id-fido-gen-ce-sernum extension.") {
      val goodCert: X509Certificate = TestAuthenticator
        .generateAttestationCertificate(
          name = new X500Name(
            "O=Yubico, C=SE, OU=Authenticator Attestation"
          ),
          extensions = List(
            (
              idFidoGenCeSernum,
              false,
              new DEROctetString(Array[Byte](0, 1, 2, 3)),
            )
          ),
        )
        ._1

      val result = new ByteArray(
        CertificateUtil
          .parseFidoSerNumExtension(goodCert)
          .get
      )
      result should equal(ByteArray.fromHex("00010203"))
    }

  }

}
