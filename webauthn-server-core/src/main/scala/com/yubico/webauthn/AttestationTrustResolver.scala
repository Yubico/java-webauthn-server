package com.yubico.webauthn

import java.util.Optional

import com.yubico.u2f.attestation.Attestation
import com.yubico.webauthn.data.AttestationObject


trait AttestationTrustResolver {

  def resolveTrustAnchor(attestationObject: AttestationObject): Optional[Attestation]

}
