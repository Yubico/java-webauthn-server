package com.yubico.attestation.resolvers;

import com.yubico.attestation.MetadataObject;
import com.yubico.attestation.MetadataResolver;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * A {@link MetadataResolver} whose {@link #resolve(X509Certificate)} method
 * calls {@link MetadataResolver#resolve(X509Certificate)} on each of the
 * subordinate {@link MetadataResolver}s in turn, and returns the first
 * non-<code>null</code> result.
 */
public class CompositeResolver implements MetadataResolver {

    private final List<MetadataResolver> resolvers;

    public CompositeResolver(List<MetadataResolver> resolvers) {
        this.resolvers = Collections.unmodifiableList(resolvers);
    }

    @Override
    public Optional<MetadataObject> resolve(X509Certificate attestationCertificate) {
        for (MetadataResolver resolver : resolvers) {
            Optional<MetadataObject> result = resolver.resolve(attestationCertificate);
            if (result.isPresent()) {
                return result;
            }
        }
        return Optional.empty();
    }

}
