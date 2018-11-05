package com.yubico.webauthn.attestation

import com.fasterxml.jackson.databind.node.JsonNodeFactory
import com.yubico.webauthn.TestAuthenticator
import com.yubico.webauthn.attestation.resolver.SimpleResolver
import com.yubico.webauthn.data.ByteArray
import org.scalatest.Matchers
import org.scalatest.FunSpec

import scala.collection.JavaConverters._
import com.yubico.internal.util.scala.JavaConverters._
import org.junit.runner.RunWith
import org.scalatest.junit.JUnitRunner


@RunWith(classOf[JUnitRunner])
class StandardMetadataServiceSpec extends FunSpec with Matchers {

  private def jsonFactory: JsonNodeFactory = JsonNodeFactory.instance

  private val ooidA = "1.3.6.1.4.1.41482.1.1"
  private val ooidB = "1.3.6.1.4.1.41482.1.2"

  describe("StandardMetadataService") {


    describe("has a getAttestation method which") {

      val (caCert, caKey) = TestAuthenticator.generateAttestationCaCertificate()
      val (certA, _) = TestAuthenticator.generateAttestationCertificate(
        caCertAndKey = Some((caCert, caKey)),
        extensions = List((ooidA, false, new ByteArray(Array())))
      )
      val (certB, _) = TestAuthenticator.generateAttestationCertificate(
        caCertAndKey = Some((caCert, caKey)),
        extensions = List((ooidB, false, new ByteArray(Array())))
      )
      val (unknownCert, _) = TestAuthenticator.generateAttestationCertificate(
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
      val resolver = new SimpleResolver()
      resolver.addMetadata(metadataJson)

      val service: StandardMetadataService  = new StandardMetadataService(resolver)

      it("returns the trusted attestation matching the single cert passed, if it is signed by a trusted certificate.") {
        val attestationA: Attestation = service.getAttestation(certA)
        val attestationB: Attestation = service.getAttestation(certB)

        attestationA.isTrusted should be (true)
        attestationA.getDeviceProperties.get.get("deviceId") should be ("DevA")

        attestationB.isTrusted should be (true)
        attestationB.getDeviceProperties.get.get("deviceId") should be ("DevB")
      }

      it("returns an unknown attestation if the passed cert is not signed by a trusted certificate.") {
        val attestation: Attestation = service.getAttestation(unknownCert)

        attestation.isTrusted should be (false)
        attestation.getDeviceProperties.asScala shouldBe empty
      }

      it("returns the first cert in the chain if it is signed by a trusted certificate.") {
        val attestationA: Attestation = service.getAttestation(List(certA, certB).asJava)
        val attestationB: Attestation = service.getAttestation(List(certB, certA).asJava)

        attestationA.isTrusted should be (true)
        attestationA.getDeviceProperties.get.get("deviceId") should be ("DevA")

        attestationB.isTrusted should be (true)
        attestationB.getDeviceProperties.get.get("deviceId") should be ("DevB")
      }

    }

  }

}
