package com.yubico.webauthn.impl

import java.util.Optional

import com.yubico.u2f.attestation.MetadataObject
import com.yubico.webauthn.data.AttestationObject


trait AttestationTrustResolver {

  def resolveTrustAnchor(attestationObject: AttestationObject): Optional[MetadataObject]

}
