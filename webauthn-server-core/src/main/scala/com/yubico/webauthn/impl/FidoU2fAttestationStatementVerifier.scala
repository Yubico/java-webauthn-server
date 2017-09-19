package com.yubico.webauthn.impl

import java.math.BigInteger
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.spec.ECParameterSpec

import com.fasterxml.jackson.databind.node.ArrayNode
import com.fasterxml.jackson.databind.node.BinaryNode
import com.fasterxml.jackson.databind.node.ObjectNode
import com.yubico.scala.util.JavaConverters._
import com.yubico.u2f.data.messages.key.RawRegisterResponse
import com.yubico.u2f.data.messages.key.util.CertificateParser
import com.yubico.webauthn.AttestationStatementVerifier
import com.yubico.webauthn.data.AttestationObject
import com.yubico.webauthn.data.ArrayBuffer
import com.yubico.webauthn.data.AttestationType
import com.yubico.webauthn.data.Basic
import com.yubico.webauthn.data.SelfAttestation
import com.yubico.webauthn.util.WebAuthnCodecs
import org.bouncycastle.jce.ECNamedCurveTable

import scala.util.Try


object FidoU2fAttestationStatementVerifier extends AttestationStatementVerifier {

  private def isP256(params: ECParameterSpec): Boolean = {
    val p256 = ECNamedCurveTable.getParameterSpec("P-256")

    (p256.getN == params.getOrder
      && p256.getG.getAffineXCoord.toBigInteger == params.getGenerator.getAffineX
      && p256.getG.getAffineYCoord.toBigInteger == params.getGenerator.getAffineY
      && p256.getH == BigInteger.valueOf(params.getCofactor)
      )
  }

  def getAttestationStatement(attestationObject: AttestationObject): ObjectNode =
    attestationObject.attestationStatement match {
      case bytes: BinaryNode => WebAuthnCodecs.cbor.readTree(bytes.binaryValue).asInstanceOf[ObjectNode]
      case map: ObjectNode => map
    }

  private def getAttestationCertificate(attestationObject: AttestationObject): X509Certificate =
    getAttestationStatement(attestationObject).get("x5c") match {
      case null => throw new IllegalArgumentException("attStmt.x5c must be present.")
      case certs => {
        if (certs.isArray) {
          if (certs.size > 0) {
            if (certs.get(0).isBinary) {
              val attestationCertificate = CertificateParser.parseDer(certs.get(0).binaryValue)

              assert(
                attestationCertificate.getPublicKey.getAlgorithm == "EC"
                  && isP256(attestationCertificate.getPublicKey.asInstanceOf[ECPublicKey].getParams),
                "Attestation certificate for fido-u2f must have an ECDSA P-256 public key."
              )

              attestationCertificate
            } else {
              throw new IllegalArgumentException("attStmt.x5c[0] must be a binary value.")
            }
          } else {
            throw new IllegalArgumentException("attStmt.x5c must have at least one element.")
          }
        } else {
          throw new IllegalArgumentException("attStmt.x5c must be an array.")
        }
      }
    }

  private def validSelfSignature(cert: X509Certificate): Boolean =
    Try(cert.verify(cert.getPublicKey)).isSuccess

  override def getAttestationType(attestationObject: AttestationObject): AttestationType = {
    val attestationCertificate = getAttestationCertificate(attestationObject)

    if (attestationCertificate.getSubjectDN == attestationCertificate.getIssuerDN
      && validSelfSignature(attestationCertificate)
    )
      SelfAttestation
    else
      Basic
  }

  override def verifyAttestationSignature(attestationObject: AttestationObject, clientDataJsonHash: ArrayBuffer): Boolean = {
    val attestationCertificate = getAttestationCertificate(attestationObject)

    assert(
      attestationCertificate.getPublicKey.getAlgorithm == "EC"
        && isP256(attestationCertificate.getPublicKey.asInstanceOf[ECPublicKey].getParams),
      "Attestation certificate for fido-u2f must have an ECDSA P-256 public key."
    )

    attestationObject.authenticatorData.attestationData.asScala match {
      case None => throw new IllegalArgumentException("Attestation object for credential creation must have attestation data.")

      case Some(attestationData) =>
        getAttestationStatement(attestationObject).get("sig") match {
          case signature if signature.isBinary =>

            val userPublicKey = WebAuthnCodecs.coseKeyToRaw(attestationData.credentialPublicKey)
            val keyHandle = attestationData.credentialId
            val u2fRegisterResponse = new RawRegisterResponse(userPublicKey.toArray,
              keyHandle.toArray,
              attestationCertificate,
              signature.binaryValue
            )

            Try {
              u2fRegisterResponse.checkSignature(attestationObject.authenticatorData.rpIdHash.toArray, clientDataJsonHash.toArray)
            }
              .isSuccess
        }

      case _ =>
        throw new IllegalArgumentException(
          """fido-u2f attestation statement must have a "sig" property set to a DER encoded signature."""
        )
    }
  }

}
