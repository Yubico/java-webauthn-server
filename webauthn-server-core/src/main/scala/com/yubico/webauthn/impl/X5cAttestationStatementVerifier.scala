package com.yubico.webauthn.impl
import java.security.cert.X509Certificate

import com.fasterxml.jackson.databind.node.ArrayNode
import com.yubico.u2f.data.messages.key.util.CertificateParser
import com.yubico.webauthn.data.AttestationObject


trait X5cAttestationStatementVerifier {

  protected def getX5cAttestationCertificate(attestationObject: AttestationObject): Option[X509Certificate] =
    attestationObject.attestationStatement.get("x5c") match {
      case certs: ArrayNode if certs.size > 0 && certs.get(0).isBinary =>
        Some(CertificateParser.parseDer(certs.get(0).binaryValue))

      case _ => None
    }
}
