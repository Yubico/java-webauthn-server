package com.yubico.webauthn.impl

import java.util.Optional

import com.fasterxml.jackson.databind.node.ArrayNode
import com.yubico.u2f.attestation.MetadataResolver
import com.yubico.u2f.attestation.MetadataObject
import com.yubico.u2f.data.messages.key.util.CertificateParser
import com.yubico.webauthn.data.AttestationObject

import scala.collection.JavaConverters._


class FidoU2fAttestationTrustResolver(
  private val resolver: MetadataResolver,
) extends AttestationTrustResolver {

  override def resolveTrustAnchor(attestationObject: AttestationObject): Optional[MetadataObject] =
    Optional.ofNullable(
      resolver.resolve(
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
