package com.yubico.webauthn.impl

import java.util.Optional

import com.fasterxml.jackson.databind.node.ArrayNode
import com.yubico.u2f.attestation.Attestation
import com.yubico.u2f.attestation.MetadataService
import com.yubico.u2f.data.messages.key.util.CertificateParser
import com.yubico.webauthn.AttestationTrustResolver
import com.yubico.webauthn.data.AttestationObject

import scala.collection.JavaConverters._


class KnownX509TrustAnchorsTrustResolver(
  private val metadataService: MetadataService
) extends AttestationTrustResolver {

  override def resolveTrustAnchor(attestationObject: AttestationObject): Optional[Attestation] =
    Optional.ofNullable(
      metadataService.getAttestation(
        attestationObject
          .attestationStatement
          .get("x5c")
          .asInstanceOf[ArrayNode]
          .iterator
          .asScala
          .map { node => CertificateParser.parseDer(node.binaryValue) }
          .toList
          .asJava
      )
    )

}
