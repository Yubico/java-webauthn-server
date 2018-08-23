/* Copyright 2015 Yubico */

package com.yubico.attestation;

import java.security.cert.X509Certificate;

public interface MetadataResolver {
    MetadataObject resolve(X509Certificate attestationCertificate);
}
