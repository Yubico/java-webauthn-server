package com.yubico.webauthn.impl
import java.security.cert.X509Certificate

import com.fasterxml.jackson.databind.node.ArrayNode
import com.yubico.u2f.data.messages.key.util.CertificateParser
import com.yubico.webauthn.data.AttestationObject


trait X5cAttestationStatementVerifier {

  protected def getX5cAttestationCertificate(attestationObject: AttestationObject): Option[X509Certificate] =
    getAttestationTrustPath(attestationObject) flatMap { _.headOption }

  def getAttestationTrustPath(attestationObject: AttestationObject): Option[List[X509Certificate]] =
    attestationObject.attestationStatement.get("x5c") match {
      case certs: ArrayNode =>
        Some((for {
          i <- 0 until certs.size
          binary = certs.get(i)
        } yield {
          if (binary.isBinary)
            CertificateParser.parseDer(certs.get(i).binaryValue)
          else
            throw new IllegalArgumentException(
              s"""Each element of "x5c" property of attestation statement must be a binary value, was: ${binary.getNodeType}"""
            )
        }).toList)

      case _ => None
    }

}
