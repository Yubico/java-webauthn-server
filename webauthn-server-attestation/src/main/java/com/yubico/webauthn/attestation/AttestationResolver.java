/* Copyright 2015 Yubico */

package com.yubico.webauthn.attestation;

import java.security.cert.X509Certificate;
import java.util.Optional;

public interface AttestationResolver {

    Optional<Attestation> resolve(X509Certificate attestationCertificate, Optional<X509Certificate> trustAnchor);
    Attestation untrustedFromCertificate(X509Certificate attestationCertificate);

}
