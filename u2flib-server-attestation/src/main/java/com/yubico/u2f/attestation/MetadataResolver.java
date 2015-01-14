package com.yubico.u2f.attestation;

import java.security.cert.X509Certificate;

/**
 * Created by dain on 12/5/14.
 */
public interface MetadataResolver {
    MetadataObject resolve(X509Certificate attestationCertificate);
}
