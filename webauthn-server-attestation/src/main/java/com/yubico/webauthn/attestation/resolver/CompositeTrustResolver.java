package com.yubico.webauthn.attestation.resolver;

import com.yubico.webauthn.attestation.TrustResolver;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * A {@link TrustResolver} whose {@link #resolveTrustAnchor(X509Certificate,
 * List)} method calls {@link TrustResolver#resolveTrustAnchor(X509Certificate,
 * List)} on each of the subordinate {@link TrustResolver}s in turn, and
 * returns the first non-<code>null</code> result.
 */
public class CompositeTrustResolver implements TrustResolver {

    private final List<TrustResolver> resolvers;

    public CompositeTrustResolver(List<TrustResolver> resolvers) {
        this.resolvers = Collections.unmodifiableList(resolvers);
    }

    @Override
    public Optional<X509Certificate> resolveTrustAnchor(X509Certificate attestationCertificate, List<X509Certificate> certificateChain) {
        for (TrustResolver resolver : resolvers) {
            Optional<X509Certificate> result = resolver.resolveTrustAnchor(attestationCertificate, certificateChain);
            if (result.isPresent()) {
                return result;
            }
        }
        return Optional.empty();
    }
}
