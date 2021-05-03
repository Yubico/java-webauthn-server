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

import com.yubico.internal.util.JacksonCodecs
import com.yubico.internal.util.scala.JavaConverters._
import com.yubico.webauthn.TestAuthenticator
import com.yubico.webauthn.attestation.resolver.SimpleAttestationResolver
import com.yubico.webauthn.attestation.resolver.SimpleTrustResolver
import org.bouncycastle.asn1.DERBitString
import org.bouncycastle.asn1.DEROctetString
import org.bouncycastle.asn1.x500.X500Name
import org.junit.runner.RunWith
import org.scalatest.FunSpec
import org.scalatest.Matchers
import org.scalatestplus.junit.JUnitRunner

import java.security.cert.X509Certificate
import java.util.Base64
import java.util.Collections
import scala.jdk.CollectionConverters._

@RunWith(classOf[JUnitRunner])
class StandardMetadataServiceSpec extends FunSpec with Matchers {

  private val TRANSPORTS_EXT_OID = "1.3.6.1.4.1.45724.2.1.1"

  private val ooidA = "1.3.6.1.4.1.41482.1.1"
  private val ooidB = "1.3.6.1.4.1.41482.1.2"

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

  def toPem(cert: X509Certificate): String =
    (
      "-----BEGIN CERTIFICATE-----\n"
        + Base64
          .getMimeEncoder(
            64,
            System.getProperty("line.separator").getBytes("UTF-8"),
          )
          .encodeToString(cert.getEncoded)
        + "\n-----END CERTIFICATE-----\n"
    )

  describe("StandardMetadataService") {

    describe("has a getAttestation method which") {

      val cacaca = TestAuthenticator.generateAttestationCaCertificate(
        name = new X500Name("CN=CA CA CA"),
        extensions = List((ooidB, false, new DEROctetString(Array[Byte]()))),
      )
      val caca = TestAuthenticator.generateAttestationCaCertificate(
        name = new X500Name("CN=CA CA"),
        superCa = Some(cacaca),
        extensions = List((ooidB, false, new DEROctetString(Array[Byte]()))),
      )
      val (caCert, caKey) = TestAuthenticator.generateAttestationCaCertificate(
        name = new X500Name("CN=CA"),
        superCa = Some(caca),
        extensions = List((ooidB, false, new DEROctetString(Array[Byte]()))),
      )

      val (certA, _) = TestAuthenticator.generateAttestationCertificate(
        name = new X500Name("CN=Cert A"),
        caCertAndKey = Some((caCert, caKey)),
        extensions = List(
          (ooidA, false, new DEROctetString(Array[Byte]())),
          (TRANSPORTS_EXT_OID, false, new DERBitString(Array[Byte](0x60))),
        ),
      )
      val (certB, _) = TestAuthenticator.generateAttestationCertificate(
        name = new X500Name("CN=Cert B"),
        caCertAndKey = Some((caCert, caKey)),
        extensions = List((ooidB, false, new DEROctetString(Array[Byte]()))),
      )

      val metadataJson =
        s"""{
          "identifier": "44c87ead-4455-423e-88eb-9248e0ebe847",
          "version": 1,
          "trustedCertificates": ["${toPem(caCert).linesIterator.mkString(
          raw"\n"
        )}"],
          "vendorInfo": {},
          "devices": [
            {
              "deviceId": "DevA",
              "displayName": "Device A",
              "selectors": [
                {
                  "type": "x509Extension",
                  "parameters": {
                    "key": "${ooidA}"
                  }
                }
              ]
            },
            {
              "deviceId": "DevB",
              "displayName": "Device B",
              "selectors": [
                {
                  "type": "x509Extension",
                  "parameters": {
                    "key": "${ooidB}"
                  }
                }
              ]
            }
          ]
        }"""
      val service = metadataService(metadataJson)

      it("returns the trusted attestation matching the single cert passed, if it is signed by a trusted certificate.") {
        val attestationA: Attestation =
          service.getAttestation(List(certA).asJava)
        val attestationB: Attestation =
          service.getAttestation(List(certB).asJava)

        attestationA.isTrusted should be(true)
        attestationA.getDeviceProperties.get.get("deviceId") should be("DevA")

        attestationB.isTrusted should be(true)
        attestationB.getDeviceProperties.get.get("deviceId") should be("DevB")
      }

      it("returns the trusted attestation matching the first cert in the chain if it is signed by a trusted certificate.") {
        val attestationA: Attestation =
          service.getAttestation(List(certA, certB).asJava)
        val attestationB: Attestation =
          service.getAttestation(List(certB, certA).asJava)

        attestationA.isTrusted should be(true)
        attestationA.getDeviceProperties.get.get("deviceId") should be("DevA")

        attestationB.isTrusted should be(true)
        attestationB.getDeviceProperties.get.get("deviceId") should be("DevB")
      }

      it("returns a trusted best-effort attestation if the certificate is trusted but matches no known metadata.") {
        val metadataJson =
          s"""{
          "identifier": "44c87ead-4455-423e-88eb-9248e0ebe847",
          "version": 1,
          "trustedCertificates": ["${toPem(caCert).linesIterator.mkString(
            raw"\n"
          )}"],
          "vendorInfo": {},
          "devices": []
        }"""
        val service = metadataService(metadataJson)

        val attestation: Attestation =
          service.getAttestation(List(certA).asJava)

        attestation.isTrusted should be(true)
        attestation.getDeviceProperties.asScala shouldBe empty
        attestation.getTransports.get.asScala should equal(
          Set(Transport.BLE, Transport.USB)
        )
      }

      it("returns an untrusted attestation with transports if the certificate is not trusted.") {
        val metadataJson =
          s"""{
          "identifier": "44c87ead-4455-423e-88eb-9248e0ebe847",
          "version": 1,
          "trustedCertificates": [],
          "vendorInfo": {},
          "devices": []
        }"""
        val service = metadataService(metadataJson)

        val attestation: Attestation =
          service.getAttestation(List(certA).asJava)

        attestation.isTrusted should be(false)
        attestation.getMetadataIdentifier.asScala shouldBe empty
        attestation.getVendorProperties.asScala shouldBe empty
        attestation.getDeviceProperties.asScala shouldBe empty
        attestation.getTransports.get.asScala should equal(
          Set(Transport.BLE, Transport.USB)
        )
      }

      it("returns the trusted attestation matching the first cert in the chain if the chain resolves to a trusted certificate.") {
        val metadataJson =
          s"""{
          "identifier": "44c87ead-4455-423e-88eb-9248e0ebe847",
          "version": 1,
          "trustedCertificates": ["${toPem(cacaca._1).linesIterator
            .mkString(raw"\n")}"],
          "vendorInfo": {},
          "devices": [
            {
              "deviceId": "DevA",
              "displayName": "Device A",
              "selectors": [
                {
                  "type": "x509Extension",
                  "parameters": {
                    "key": "${ooidA}"
                  }
                }
              ]
            }
          ]
        }"""
        val service = metadataService(metadataJson)

        val attestation: Attestation =
          service.getAttestation(List(certA, caCert, caca._1).asJava)

        attestation.isTrusted should be(true)
        attestation.getDeviceProperties.get.get("deviceId") should be("DevA")
      }

      it("matches any certificate to a device with no selectors.") {
        val metadataJson =
          s"""{
          "identifier": "44c87ead-4455-423e-88eb-9248e0ebe847",
          "version": 1,
          "trustedCertificates": ["${toPem(caCert).linesIterator.mkString(
            raw"\n"
          )}"],
          "vendorInfo": {},
          "devices": [
            {
              "deviceId": "DevA",
              "displayName": "Device A"
            }
          ]
        }"""
        val service = metadataService(metadataJson)

        val resultA = service.getAttestation(List(certA).asJava)
        val resultB = service.getAttestation(List(certB).asJava)
        resultA.getDeviceProperties.get.get("deviceId") should be("DevA")
        resultB.getDeviceProperties.get.get("deviceId") should be("DevA")
      }

    }

  }

}
