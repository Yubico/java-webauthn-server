package com.yubico.webauthn.attestation.resolver;

import com.google.common.collect.ArrayListMultimap;
import com.google.common.collect.Multimap;
import com.yubico.webauthn.attestation.TrustResolver;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.List;
import java.util.Optional;

/**
 * Resolves a metadata object whose associated certificate has signed the
 * argument certificate, or is equal to the argument certificate.
 */
public class SimpleTrustResolverWithEquality implements TrustResolver {

    private final SimpleTrustResolver subresolver;
    private final Multimap<String, X509Certificate> trustedCerts = ArrayListMultimap.create();

    public SimpleTrustResolverWithEquality(Collection<X509Certificate> trustedCertificates) {
        subresolver = new SimpleTrustResolver(trustedCertificates);

        for (X509Certificate cert : trustedCertificates) {
            trustedCerts.put(cert.getSubjectDN().getName(), cert);
        }
    }

    @Override
    public Optional<X509Certificate> resolveTrustAnchor(X509Certificate attestationCertificate, List<X509Certificate> caCertificateChain) {
        Optional<X509Certificate> subResult = subresolver.resolveTrustAnchor(attestationCertificate, caCertificateChain);

        if (subResult.isPresent()) {
            return subResult;
        } else {
            for (X509Certificate cert : trustedCerts.get(attestationCertificate.getSubjectDN().getName())) {
                if (cert.equals(attestationCertificate)) {
                    return Optional.of(cert);
                }
            }

            return Optional.empty();
        }
    }

}
