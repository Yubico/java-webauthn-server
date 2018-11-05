package com.yubico.webauthn.attestation

import com.fasterxml.jackson.databind.node.JsonNodeFactory
import com.yubico.internal.util.scala.JavaConverters._
import com.yubico.webauthn.TestAuthenticator
import com.yubico.webauthn.data.ByteArray
import org.bouncycastle.asn1.x500.X500Name
import org.junit.runner.RunWith
import org.scalatest.Matchers
import org.scalatest.FunSpec
import org.scalatest.junit.JUnitRunner

import scala.collection.JavaConverters._


@RunWith(classOf[JUnitRunner])
class StandardMetadataServiceSpec extends FunSpec with Matchers {

  private def jsonFactory: JsonNodeFactory = JsonNodeFactory.instance

  private val ooidA = "1.3.6.1.4.1.41482.1.1"
  private val ooidB = "1.3.6.1.4.1.41482.1.2"

  describe("StandardMetadataService") {

    describe("has a getAttestation method which") {

      val cacaca = TestAuthenticator.generateAttestationCaCertificate(
        name = new X500Name("CN=CA CA CA"),
        extensions = List((ooidB, false, new ByteArray(Array())))
      )
      val caca = TestAuthenticator.generateAttestationCaCertificate(
        name = new X500Name("CN=CA CA"),
        superCa = Some(cacaca),
        extensions = List((ooidB, false, new ByteArray(Array())))
      )
      val (caCert, caKey) = TestAuthenticator.generateAttestationCaCertificate(
        name = new X500Name("CN=CA"),
        superCa = Some(caca),
        extensions = List((ooidB, false, new ByteArray(Array())))
      )

      val (certA, _) = TestAuthenticator.generateAttestationCertificate(
        name = new X500Name("CN=Cert A"),
        caCertAndKey = Some((caCert, caKey)),
        extensions = List((ooidA, false, new ByteArray(Array())))
      )
      val (certB, _) = TestAuthenticator.generateAttestationCertificate(
        name = new X500Name("CN=Cert B"),
        caCertAndKey = Some((caCert, caKey)),
        extensions = List((ooidB, false, new ByteArray(Array())))
      )
      val (unknownCert, _) = TestAuthenticator.generateAttestationCertificate(
        name = new X500Name("CN=Unknown Cert"),
        extensions = List((ooidA, false, new ByteArray(Array())))
      )

      val metadataJson =
        s"""{
          "identifier": "44c87ead-4455-423e-88eb-9248e0ebe847",
          "version": 1,
          "trustedCertificates": ["${TestAuthenticator.toPem(caCert).lines.mkString(raw"\n")}"],
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
      val service: StandardMetadataService  = StandardMetadataService.usingMetadataJson(metadataJson)

      it("returns the trusted attestation matching the single cert passed, if it is signed by a trusted certificate.") {
        val attestationA: Attestation = service.getAttestation(List(certA).asJava)
        val attestationB: Attestation = service.getAttestation(List(certB).asJava)

        attestationA.isTrusted should be (true)
        attestationA.getDeviceProperties.get.get("deviceId") should be ("DevA")

        attestationB.isTrusted should be (true)
        attestationB.getDeviceProperties.get.get("deviceId") should be ("DevB")
      }

      it("returns an unknown attestation if the passed cert is not signed by a trusted certificate.") {
        val attestation: Attestation = service.getAttestation(List(unknownCert).asJava)

        attestation.isTrusted should be (false)
        attestation.getDeviceProperties.asScala shouldBe empty
      }

      it("returns the trusted attestation matching the first cert in the chain if it is signed by a trusted certificate.") {
        val attestationA: Attestation = service.getAttestation(List(certA, certB).asJava)
        val attestationB: Attestation = service.getAttestation(List(certB, certA).asJava)

        attestationA.isTrusted should be (true)
        attestationA.getDeviceProperties.get.get("deviceId") should be ("DevA")

        attestationB.isTrusted should be (true)
        attestationB.getDeviceProperties.get.get("deviceId") should be ("DevB")
      }

      it("returns the trusted attestation matching the first cert in the chain if the chain resolves to a trusted certificate.") {
        val metadataJson =
          s"""{
          "identifier": "44c87ead-4455-423e-88eb-9248e0ebe847",
          "version": 1,
          "trustedCertificates": ["${TestAuthenticator.toPem(cacaca._1).lines.mkString(raw"\n")}"],
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
        val service: StandardMetadataService = StandardMetadataService.usingMetadataJson(metadataJson)

        val attestation: Attestation = service.getAttestation(List(certA, caCert, caca._1).asJava)

        attestation.isTrusted should be (true)
        attestation.getDeviceProperties.get.get("deviceId") should be ("DevA")
      }

    }

  }

}
