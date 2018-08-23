package com.yubico.webauthn;

import com.yubico.u2f.attestation.Attestation;
import com.yubico.webauthn.data.AttestationObject;
import java.util.Optional;


public interface AttestationTrustResolver {

  Optional<Attestation> resolveTrustAnchor(AttestationObject attestationObject);

}
