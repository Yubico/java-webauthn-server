package com.yubico.attestation.resolver;

import com.yubico.attestation.MetadataObject;
import java.security.cert.X509Certificate;
import java.util.Optional;

/**
 * Resolves a metadata object whose associated certificate has signed the
 * argument certificate, or is equal to the argument certificate.
 */
public class SimpleResolverWithEquality extends SimpleResolver {

    @Override
    public Optional<MetadataObject> resolve(X509Certificate attestationCertificate) {
        Optional<MetadataObject> parentResult = super.resolve(attestationCertificate);

        if (parentResult.isPresent()) {
            return parentResult;
        } else {
            for (X509Certificate cert : certs.get(attestationCertificate.getSubjectDN().getName())) {
                if (cert.equals(attestationCertificate)) {
                    return Optional.of(metadata.get(cert));
                }
            }

            return Optional.empty();
        }
    }

}
