/* Copyright 2015 Yubico */

package com.yubico.webauthn.attestation;

import java.security.cert.X509Certificate;
import java.util.Optional;

public interface MetadataResolver {
    Optional<MetadataObject> resolve(X509Certificate attestationCertificate);
}
