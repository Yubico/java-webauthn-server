package com.yubico.webauthn

import com.fasterxml.jackson.databind.node.ArrayNode
import com.yubico.scala.util.JavaConverters._
import com.yubico.u2f.data.messages.key.RawRegisterResponse
import com.yubico.u2f.data.messages.key.util.CertificateParser
import com.yubico.webauthn.data.AttestationObject
import com.yubico.webauthn.data.ArrayBuffer
import com.yubico.webauthn.util.WebAuthnCodecs

import scala.util.Try


object FidoU2fAttestationStatementVerifier extends AttestationStatementVerifier {

  override def verifyAttestationSignature(attestationObject: AttestationObject, clientDataJsonHash: ArrayBuffer): Boolean =

    attestationObject.authenticatorData.attestationData.asScala match {
      case None => throw new IllegalArgumentException("Attestation object for credential creation must have attestation data.")

      case Some(attestationData) =>
        attestationObject.attestationStatement.get("sig") match {
          case signature if signature.isBinary =>
            attestationObject.attestationStatement.get("x5c") match {
              case certs: ArrayNode if certs.size > 0 && certs.get(0).isBinary => {

                val userPublicKey = WebAuthnCodecs.coseKeyToRaw(attestationData.credentialPublicKey)
                val keyHandle = attestationData.credentialId
                val attestationCertificate = CertificateParser.parseDer(certs.get(0).binaryValue)

                val u2fRegisterResponse = new RawRegisterResponse(userPublicKey.toArray,
                  keyHandle.toArray,
                  attestationCertificate,
                  signature.binaryValue
                )

                Try { u2fRegisterResponse.checkSignature(attestationObject.authenticatorData.rpIdHash.toArray, clientDataJsonHash.toArray) }
                  .isSuccess
              }

              case _ => throw new IllegalArgumentException(
                """fido-u2f attestation statement must have an "x5c" property set to an array of at least one DER encoded X.509 certificate."""
              )
            }
          case _ => throw new IllegalArgumentException(
            """fido-u2f attestation statement must have a "sig" property set to a DER encoded signature."""
          )
        }
    }


}
