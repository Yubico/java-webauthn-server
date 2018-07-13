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
    getX5cAttestationCertificate(attestationObject).asScala match {
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
      && (WebAuthnCodecs.ecPublicKeyToRaw(attestationObject.getAuthenticatorData.getAttestationData.get.getParsedCredentialPublicKey) sameElements WebAuthnCodecs.ecPublicKeyToRaw(attestationCertificate.getPublicKey.asInstanceOf[ECPublicKey]))
    )
      AttestationType.SELF_ATTESTATION
    else
      AttestationType.BASIC
  }

  override def verifyAttestationSignature(attestationObject: AttestationObject, clientDataJsonHash: Array[Byte]): Boolean = {
    val attestationCertificate = getAttestationCertificate(attestationObject)

    assert(
      attestationCertificate.getPublicKey.getAlgorithm == "EC"
        && isP256(attestationCertificate.getPublicKey.asInstanceOf[ECPublicKey].getParams),
      "Attestation certificate for fido-u2f must have an ECDSA P-256 public key."
    )

    attestationObject.getAuthenticatorData.getAttestationData.asScala match {
      case None => throw new IllegalArgumentException("Attestation object for credential creation must have attestation data.")

      case Some(attestationData) =>
        attestationObject.getAttestationStatement.get("sig") match {
          case signature if signature.isBinary =>

            val userPublicKey = WebAuthnCodecs.ecPublicKeyToRaw(attestationData.getParsedCredentialPublicKey)
            val keyHandle = attestationData.getCredentialId
            val u2fRegisterResponse = new RawRegisterResponse(userPublicKey,
              keyHandle,
              attestationCertificate,
              signature.binaryValue
            )

            Try {
              u2fRegisterResponse.checkSignature(attestationObject.getAuthenticatorData.getRpIdHash, clientDataJsonHash.toArray)
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
