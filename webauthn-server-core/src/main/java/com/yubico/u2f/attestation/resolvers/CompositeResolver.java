package com.yubico.u2f.attestation.resolvers;

import com.yubico.u2f.attestation.MetadataObject;
import com.yubico.u2f.attestation.MetadataResolver;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

public class CompositeResolver implements MetadataResolver {

    private final List<MetadataResolver> resolvers;

    public CompositeResolver(List<MetadataResolver> resolvers) {
        this.resolvers = Collections.unmodifiableList(resolvers);
    }

    @Override
    public MetadataObject resolve(X509Certificate attestationCertificate) {
        for (MetadataResolver resolver : resolvers) {
            MetadataObject result = resolver.resolve(attestationCertificate);
            if (result != null) {
                return result;
            }
        }
        return null;
    }

}
