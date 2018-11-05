package com.yubico.webauthn.attestation.resolver;

import com.yubico.webauthn.attestation.Attestation;
import com.yubico.webauthn.attestation.AttestationResolver;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * An {@link AttestationResolver} whose {@link #resolve(X509Certificate,
 * Optional)} method calls {@link AttestationResolver#resolve(X509Certificate,
 * Optional)} on each of the subordinate {@link AttestationResolver}s in turn,
 * and returns the first non-<code>null</code> result.
 */
public class CompositeAttestationResolver implements AttestationResolver {

    private final List<AttestationResolver> resolvers;

    public CompositeAttestationResolver(List<AttestationResolver> resolvers) {
        this.resolvers = Collections.unmodifiableList(resolvers);
    }

    @Override
    public Optional<Attestation> resolve(X509Certificate attestationCertificate, Optional<X509Certificate> trustAnchor) {
        for (AttestationResolver resolver : resolvers) {
            Optional<Attestation> result = resolver.resolve(attestationCertificate, trustAnchor);
            if (result.isPresent()) {
                return result;
            }
        }
        return Optional.empty();
    }

    /**
     * Delegates to the first subordinate resolver, or throws an exception if there is none.
     */
    @Override
    public Attestation untrustedFromCertificate(X509Certificate attestationCertificate) {
        if (resolvers.isEmpty()) {
            throw new UnsupportedOperationException("Cannot do this without any sub-resolver.");
        } else {
            return resolvers.get(0).untrustedFromCertificate(attestationCertificate);
        }
    }

}
