package com.yubico.webauthn.attestation.resolver;

import com.yubico.internal.util.CertificateParser;
import com.yubico.internal.util.WebAuthnCodecs;
import com.yubico.webauthn.attestation.MetadataObject;
import com.yubico.webauthn.attestation.MetadataResolver;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Resolves a metadata object where the argument certificate is listed as a
 * trusted root certificate.
 */
public class SimpleMetadataResolver implements MetadataResolver {

    private final Map<X509Certificate, MetadataObject> metadata = new HashMap<>();

    public SimpleMetadataResolver(Collection<MetadataObject> objects) throws CertificateException {
        for (MetadataObject object : objects) {
            for (String caPem : object.getTrustedCertificates()) {
                X509Certificate trustAnchor = CertificateParser.parsePem(caPem);
                metadata.put(trustAnchor, object);
            }
        }
    }

    public static SimpleMetadataResolver fromMetadataJson(String metadataObjectJson) throws IOException, CertificateException {
        return new SimpleMetadataResolver(Collections.singleton(WebAuthnCodecs.json().readValue(metadataObjectJson, MetadataObject.class)));
    }

    @Override
    public Optional<MetadataObject> resolve(X509Certificate trustAnchor) {
        return Optional.ofNullable(metadata.get(trustAnchor));
    }

}
