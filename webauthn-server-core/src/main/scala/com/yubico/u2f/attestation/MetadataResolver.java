/* Copyright 2015 Yubico */

package com.yubico.u2f.attestation;

import java.security.cert.X509Certificate;

public interface MetadataResolver {
    MetadataObject resolve(X509Certificate attestationCertificate);
}
