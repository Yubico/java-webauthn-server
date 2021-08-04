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

package com.yubico.webauthn.attestation

import com.yubico.internal.util.CertificateParser
import com.yubico.internal.util.JacksonCodecs
import com.yubico.webauthn.FinishRegistrationOptions
import com.yubico.webauthn.RelyingParty
import com.yubico.webauthn.attestation.Transport.LIGHTNING
import com.yubico.webauthn.attestation.Transport.NFC
import com.yubico.webauthn.attestation.Transport.USB
import com.yubico.webauthn.attestation.resolver.SimpleAttestationResolver
import com.yubico.webauthn.attestation.resolver.SimpleTrustResolver
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions
import com.yubico.webauthn.data.PublicKeyCredentialParameters
import com.yubico.webauthn.test.Helpers
import com.yubico.webauthn.test.RealExamples
import org.junit.runner.RunWith
import org.scalatest.FunSpec
import org.scalatest.Matchers
import org.scalatestplus.junit.JUnitRunner

import java.util.Collections
import scala.jdk.CollectionConverters._

@RunWith(classOf[JUnitRunner])
class DeviceIdentificationSpec extends FunSpec with Matchers {

  def metadataService(metadataJson: String): StandardMetadataService = {
    val metadata = Collections.singleton(
      JacksonCodecs.json().readValue(metadataJson, classOf[MetadataObject])
    )
    new StandardMetadataService(
      new SimpleAttestationResolver(
        metadata,
        SimpleTrustResolver.fromMetadata(metadata),
      )
    )
  }

  describe("A RelyingParty with the default StandardMetadataService") {

    describe("correctly identifies") {
      def check(
          expectedName: String,
          testData: RealExamples.Example,
          transports: Set[Transport],
      ): Unit = {
        val rp = RelyingParty
          .builder()
          .identity(testData.rp)
          .credentialRepository(Helpers.CredentialRepository.empty)
          .metadataService(new StandardMetadataService())
          .allowUnrequestedExtensions(true)
          .build()

        val result = rp.finishRegistration(
          FinishRegistrationOptions
            .builder()
            .request(
              PublicKeyCredentialCreationOptions
                .builder()
                .rp(testData.rp)
                .user(testData.user)
                .challenge(testData.attestation.challenge)
                .pubKeyCredParams(
                  List(
                    PublicKeyCredentialParameters.ES256,
                    PublicKeyCredentialParameters.EdDSA,
                  ).asJava
                )
                .build()
            )
            .response(testData.attestation.credential)
            .build()
        );

        result.isAttestationTrusted should be(true)
        result.getAttestationMetadata.isPresent should be(true)
        result.getAttestationMetadata.get.getDeviceProperties.isPresent should be(
          true
        )
        result.getAttestationMetadata.get.getDeviceProperties
          .get()
          .get("displayName") should equal(expectedName)
        result.getAttestationMetadata.get.getTransports.isPresent should be(
          true
        )
        result.getAttestationMetadata.get.getTransports.get.asScala should equal(
          transports
        )
      }

      it("a YubiKey NEO.") {
        check("YubiKey NEO/NEO-n", RealExamples.YubiKeyNeo, Set(USB, NFC))
      }
      it("a YubiKey 4.") {
        check("YubiKey 4/YubiKey 4 Nano", RealExamples.YubiKey4, Set(USB))
      }
      it("a YubiKey 5 NFC.") {
        check("YubiKey 5 NFC", RealExamples.YubiKey5, Set(USB, NFC))
      }
      it("an early YubiKey 5 NFC.") {
        check("YubiKey 5 NFC", RealExamples.YubiKey5Nfc, Set(USB, NFC))
      }
      it("a newer YubiKey 5 NFC.") {
        check(
          "YubiKey 5/5C NFC",
          RealExamples.YubiKey5NfcPost5cNfc,
          Set(USB, NFC),
        )
      }
      it("a YubiKey 5C NFC.") {
        check("YubiKey 5/5C NFC", RealExamples.YubiKey5cNfc, Set(USB, NFC))
      }
      it("a YubiKey 5 Nano.") {
        check("YubiKey 5 Series", RealExamples.YubiKey5Nano, Set(USB))
      }
      it("a YubiKey 5Ci.") {
        check("YubiKey 5Ci", RealExamples.YubiKey5Ci, Set(USB, LIGHTNING))
      }
      it("a Security Key by Yubico.") {
        check("Security Key by Yubico", RealExamples.SecurityKey, Set(USB))
      }
      it("a Security Key 2 by Yubico.") {
        check("Security Key by Yubico", RealExamples.SecurityKey2, Set(USB))
      }
      it("a Security Key NFC by Yubico.") {
        check(
          "Security Key NFC by Yubico",
          RealExamples.SecurityKeyNfc,
          Set(USB, NFC),
        )
      }

      it("a YubiKey 5.4 NFC FIPS.") {
        check(
          "YubiKey 5/5C NFC FIPS",
          RealExamples.YubikeyFips5Nfc,
          Set(USB, NFC),
        )
      }
      it("a YubiKey 5.4 Ci FIPS.") {
        check(
          "YubiKey 5Ci FIPS",
          RealExamples.Yubikey5ciFips,
          Set(USB, LIGHTNING),
        )
      }

      it("a YubiKey Bio.") {
        check(
          "YubiKey Bio - FIDO Edition",
          RealExamples.YubikeyBio_5_5_4,
          Set(USB),
        )
        check(
          "YubiKey Bio - FIDO Edition",
          RealExamples.YubikeyBio_5_5_5,
          Set(USB),
        )
      }
    }

    describe("fails to identify") {
      def check(testData: RealExamples.Example): Unit = {
        val rp = RelyingParty
          .builder()
          .identity(testData.rp)
          .credentialRepository(Helpers.CredentialRepository.empty)
          .metadataService(new StandardMetadataService())
          .build()

        val result = rp.finishRegistration(
          FinishRegistrationOptions
            .builder()
            .request(
              PublicKeyCredentialCreationOptions
                .builder()
                .rp(testData.rp)
                .user(testData.user)
                .challenge(testData.attestation.challenge)
                .pubKeyCredParams(
                  List(PublicKeyCredentialParameters.ES256).asJava
                )
                .build()
            )
            .response(testData.attestation.credential)
            .build()
        );

        result.isAttestationTrusted should be(false)
        result.getAttestationMetadata.isPresent should be(true)
        result.getAttestationMetadata.get.getDeviceProperties.isPresent should be(
          false
        )
        result.getAttestationMetadata.get.getVendorProperties.isPresent should be(
          false
        )
        result.getAttestationMetadata.get.getTransports.isPresent should be(
          false
        )
      }

      it("an Apple iOS device.") {
        check(RealExamples.AppleAttestationIos)
      }
    }
  }

  describe("The default AttestationResolver") {
    describe("successfully identifies") {
      def check(
          expectedName: String,
          testData: RealExamples.Example,
          transports: Set[Transport],
      ): Unit = {
        val cert = CertificateParser.parseDer(testData.attestationCert.getBytes)
        val resolved = StandardMetadataService
          .createDefaultAttestationResolver()
          .resolve(cert)
        resolved.isPresent should be(true)
        resolved.get.getDeviceProperties.isPresent should be(true)
        resolved.get.getDeviceProperties.get.get("displayName") should equal(
          expectedName
        )
        resolved.get.getTransports.isPresent should be(true)
        resolved.get.getTransports.get.asScala should equal(transports)
      }

      it("a YubiKey NEO.") {
        check("YubiKey NEO/NEO-n", RealExamples.YubiKeyNeo, Set(USB, NFC))
      }
      it("a YubiKey 4.") {
        check("YubiKey 4/YubiKey 4 Nano", RealExamples.YubiKey4, Set(USB))
      }
      it("a YubiKey 5 NFC.") {
        check("YubiKey 5 NFC", RealExamples.YubiKey5, Set(USB, NFC))
      }
      it("an early YubiKey 5 NFC.") {
        check("YubiKey 5 NFC", RealExamples.YubiKey5Nfc, Set(USB, NFC))
      }
      it("a newer YubiKey 5 NFC.") {
        check(
          "YubiKey 5/5C NFC",
          RealExamples.YubiKey5NfcPost5cNfc,
          Set(USB, NFC),
        )
      }
      it("a YubiKey 5C NFC.") {
        check("YubiKey 5/5C NFC", RealExamples.YubiKey5cNfc, Set(USB, NFC))
      }
      it("a YubiKey 5 Nano.") {
        check("YubiKey 5 Series", RealExamples.YubiKey5Nano, Set(USB))
      }
      it("a YubiKey 5Ci.") {
        check("YubiKey 5Ci", RealExamples.YubiKey5Ci, Set(USB, LIGHTNING))
      }
      it("a Security Key by Yubico.") {
        check("Security Key by Yubico", RealExamples.SecurityKey, Set(USB))
      }
      it("a Security Key 2 by Yubico.") {
        check("Security Key by Yubico", RealExamples.SecurityKey2, Set(USB))
      }
      it("a Security Key NFC by Yubico.") {
        check(
          "Security Key NFC by Yubico",
          RealExamples.SecurityKeyNfc,
          Set(USB, NFC),
        )
      }

      it("a YubiKey 5.4 NFC FIPS.") {
        check(
          "YubiKey 5/5C NFC FIPS",
          RealExamples.YubikeyFips5Nfc,
          Set(USB, NFC),
        )
      }
      it("a YubiKey 5.4 Ci FIPS.") {
        check(
          "YubiKey 5Ci FIPS",
          RealExamples.Yubikey5ciFips,
          Set(USB, LIGHTNING),
        )
      }

      it("a YubiKey Bio.") {
        check(
          "YubiKey Bio - FIDO Edition",
          RealExamples.YubikeyBio_5_5_4,
          Set(USB),
        )
        check(
          "YubiKey Bio - FIDO Edition",
          RealExamples.YubikeyBio_5_5_5,
          Set(USB),
        )
      }
    }
  }

  describe(
    "A StandardMetadataService configured with an Apple root certificate"
  ) {
    // Apple WebAuthn Root CA cert downloaded from https://www.apple.com/certificateauthority/private/ on 2021-04-12
    // https://www.apple.com/certificateauthority/Apple_WebAuthn_Root_CA.pem
    val mds = metadataService("""{
        |  "identifier": "98cf2729-e2b9-4633-8b6a-b295cda99ccf",
        |  "version": 1,
        |  "vendorInfo": {
        |    "name": "Apple Inc. (Metadata file by Yubico)"
        |  },
        |  "trustedCertificates": [
        |    "-----BEGIN CERTIFICATE-----\nMIICEjCCAZmgAwIBAgIQaB0BbHo84wIlpQGUKEdXcTAKBggqhkjOPQQDAzBLMR8w\nHQYDVQQDDBZBcHBsZSBXZWJBdXRobiBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJ\nbmMuMRMwEQYDVQQIDApDYWxpZm9ybmlhMB4XDTIwMDMxODE4MjEzMloXDTQ1MDMx\nNTAwMDAwMFowSzEfMB0GA1UEAwwWQXBwbGUgV2ViQXV0aG4gUm9vdCBDQTETMBEG\nA1UECgwKQXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTB2MBAGByqGSM49\nAgEGBSuBBAAiA2IABCJCQ2pTVhzjl4Wo6IhHtMSAzO2cv+H9DQKev3//fG59G11k\nxu9eI0/7o6V5uShBpe1u6l6mS19S1FEh6yGljnZAJ+2GNP1mi/YK2kSXIuTHjxA/\npcoRf7XkOtO4o1qlcaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUJtdk\n2cV4wlpn0afeaxLQG2PxxtcwDgYDVR0PAQH/BAQDAgEGMAoGCCqGSM49BAMDA2cA\nMGQCMFrZ+9DsJ1PW9hfNdBywZDsWDbWFp28it1d/5w2RPkRX3Bbn/UbDTNLx7Jr3\njAGGiQIwHFj+dJZYUJR786osByBelJYsVZd2GbHQu209b5RCmGQ21gpSAk9QZW4B\n1bWeT0vT\n-----END CERTIFICATE-----"
        |  ],
        |  "devices": [
        |    {
        |      "displayName": "Apple device",
        |      "selectors": [
        |        {
        |          "type": "x509Extension",
        |          "parameters": {
        |            "key": "1.2.840.113635.100.8.2"
        |          }
        |        }
        |      ]
        |    }
        |  ]
        |}""".stripMargin)

    describe("successfully identifies") {
      def check(
          expectedName: String,
          testData: RealExamples.Example,
      ): Unit = {
        val rp = RelyingParty
          .builder()
          .identity(testData.rp)
          .credentialRepository(Helpers.CredentialRepository.empty)
          .metadataService(mds)
          .build()

        val result = rp.finishRegistration(
          FinishRegistrationOptions
            .builder()
            .request(
              PublicKeyCredentialCreationOptions
                .builder()
                .rp(testData.rp)
                .user(testData.user)
                .challenge(testData.attestation.challenge)
                .pubKeyCredParams(
                  List(PublicKeyCredentialParameters.ES256).asJava
                )
                .build()
            )
            .response(testData.attestation.credential)
            .build()
        )

        result.isAttestationTrusted should be(true)
        result.getAttestationMetadata.isPresent should be(true)
        result.getAttestationMetadata.get.getDeviceProperties.isPresent should be(
          true
        )
        result.getAttestationMetadata.get.getDeviceProperties
          .get()
          .get("displayName") should equal(expectedName)
        result.getAttestationMetadata.get.getTransports.isPresent should be(
          false
        )
      }

      it("an Apple iOS device.") {
        check(
          "Apple device",
          RealExamples.AppleAttestationIos,
        )
      }

      it("an Apple MacOS device.") {
        check(
          "Apple device",
          RealExamples.AppleAttestationMacos,
        )
      }
    }

    describe("fails to identify") {
      def check(testData: RealExamples.Example): Unit = {
        val rp = RelyingParty
          .builder()
          .identity(testData.rp)
          .credentialRepository(Helpers.CredentialRepository.empty)
          .metadataService(mds)
          .build()

        val result = rp.finishRegistration(
          FinishRegistrationOptions
            .builder()
            .request(
              PublicKeyCredentialCreationOptions
                .builder()
                .rp(testData.rp)
                .user(testData.user)
                .challenge(testData.attestation.challenge)
                .pubKeyCredParams(
                  List(PublicKeyCredentialParameters.ES256).asJava
                )
                .build()
            )
            .response(testData.attestation.credential)
            .build()
        )

        result.isAttestationTrusted should be(false)
        result.getAttestationMetadata.isPresent should be(true)
        result.getAttestationMetadata.get.getVendorProperties.isPresent should be(
          false
        )
        result.getAttestationMetadata.get.getDeviceProperties.isPresent should be(
          false
        )
      }

      it("a YubiKey 5 NFC.") {
        check(RealExamples.YubiKey5)
      }
    }
  }

}
