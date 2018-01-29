package com.yubico.webauthn.impl

import java.math.BigInteger
import java.security.cert.X509Certificate
import java.security.interfaces.ECPublicKey
import java.security.spec.ECParameterSpec

import com.yubico.scala.util.JavaConverters._
import com.yubico.u2f.data.messages.key.RawRegisterResponse
import com.yubico.webauthn.AttestationStatementVerifier
import com.yubico.webauthn.data.AttestationObject
import com.yubico.webauthn.data.ArrayBuffer
import com.yubico.webauthn.data.AttestationType
import com.yubico.webauthn.data.Basic
import com.yubico.webauthn.data.SelfAttestation
import com.yubico.webauthn.util.WebAuthnCodecs
import org.bouncycastle.jce.ECNamedCurveTable

import scala.util.Try


object FidoU2fAttestationStatementVerifier extends AttestationStatementVerifier with X5cAttestationStatementVerifier {

  private def isP256(params: ECParameterSpec): Boolean = {
    val p256 = ECNamedCurveTable.getParameterSpec("P-256")

    (p256.getN == params.getOrder
      && p256.getG.getAffineXCoord.toBigInteger == params.getGenerator.getAffineX
      && p256.getG.getAffineYCoord.toBigInteger == params.getGenerator.getAffineY
      && p256.getH == BigInteger.valueOf(params.getCofactor)
      )
  }

  private def getAttestationCertificate(attestationObject: AttestationObject): X509Certificate =
    getX5cAttestationCertificate(attestationObject) match {
      case Some(attestationCertificate) => {
        assert(
          attestationCertificate.getPublicKey.getAlgorithm == "EC"
            && isP256(attestationCertificate.getPublicKey.asInstanceOf[ECPublicKey].getParams),
          "Attestation certificate for fido-u2f must have an ECDSA P-256 public key."
        )

        attestationCertificate
      }

      case _ => throw new IllegalArgumentException(
        """fido-u2f attestation statement must have an "x5c" property set to an array of at least one DER encoded X.509 certificate."""
      )
    }

  private def validSelfSignature(cert: X509Certificate): Boolean =
    Try(cert.verify(cert.getPublicKey)).isSuccess

  override def getAttestationType(attestationObject: AttestationObject): AttestationType = {
    val attestationCertificate = getAttestationCertificate(attestationObject)

    if (attestationCertificate.getPublicKey.isInstanceOf[ECPublicKey]
      && validSelfSignature(attestationCertificate)
      && (
        WebAuthnCodecs.ecPublicKeyToRaw(attestationObject.authenticatorData.attestationData.get.parsedCredentialPublicKey) ==
        WebAuthnCodecs.ecPublicKeyToRaw(attestationCertificate.getPublicKey.asInstanceOf[ECPublicKey])
      )
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
        attestationObject.attestationStatement.get("sig") match {
          case signature if signature.isBinary =>

            val userPublicKey = WebAuthnCodecs.ecPublicKeyToRaw(attestationData.parsedCredentialPublicKey)
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
