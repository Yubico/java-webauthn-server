/* Copyright 2015 Yubico */

package com.yubico.webauthn.attestation;

import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

public interface AttestationResolver {

    /**
     * Alias of <code>resolve(attestationCertificate, Collections.emptyList())</code>.
     */
    default Optional<Attestation> resolve(X509Certificate attestationCertificate) {
        return resolve(attestationCertificate, Collections.emptyList());
    }

    Optional<Attestation> resolve(X509Certificate attestationCertificate, List<X509Certificate> certificateChain);
    Attestation untrustedFromCertificate(X509Certificate attestationCertificate);

}
