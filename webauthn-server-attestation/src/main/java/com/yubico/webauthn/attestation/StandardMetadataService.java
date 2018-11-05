/* Copyright 2015 Yubico */

package com.yubico.webauthn.attestation;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.hash.Hashing;
import com.google.common.io.Closeables;
import com.yubico.internal.util.ExceptionUtil;
import com.yubico.internal.util.WebAuthnCodecs;
import com.yubico.webauthn.attestation.resolver.SimpleAttestationResolver;
import com.yubico.webauthn.attestation.resolver.SimpleTrustResolver;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ExecutionException;
import lombok.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class StandardMetadataService implements MetadataService {
    private static final Logger logger = LoggerFactory.getLogger(StandardMetadataService.class);

    private static MetadataObject readDefaultMetadata() {
        InputStream is = StandardMetadataService.class.getResourceAsStream("/metadata.json");
        try {
            return WebAuthnCodecs.json().readValue(is, MetadataObject.class);
        } catch (IOException e) {
            throw ExceptionUtil.wrapAndLog(logger, "Failed to read default metadata", e);
        } finally {
            Closeables.closeQuietly(is);
        }
    }

    public static TrustResolver createDefaultTrustResolver() throws CertificateException {
        return SimpleTrustResolver.fromMetadata(Collections.singleton(readDefaultMetadata()));
    }

    public static AttestationResolver createDefaultMetadataResolver() throws CertificateException {
        return new SimpleAttestationResolver(Collections.singleton(readDefaultMetadata()));
    }

    private static StandardMetadataService usingMetadata(Collection<MetadataObject> metadata) throws CertificateException {
        return new StandardMetadataService(
            SimpleTrustResolver.fromMetadata(metadata),
            new SimpleAttestationResolver(metadata)
        );
    }

    static StandardMetadataService usingMetadataJson(String metadataJson) throws CertificateException {
        Collection<MetadataObject> metadata;
        try {
            metadata = Collections.singleton(WebAuthnCodecs.json().readValue(metadataJson, MetadataObject.class));
        } catch (IOException e) {
            throw ExceptionUtil.wrapAndLog(logger, "Failed to read metadata object from json: " + metadataJson, e);
        }

        return usingMetadata(metadata);
    }

    private final Attestation unknownAttestation = Attestation.builder(false).build();
    private final TrustResolver trustResolver;
    private final AttestationResolver attestationResolver;
    private final Cache<String, Attestation> cache;

    private StandardMetadataService(
        @NonNull
        TrustResolver trustResolver,
        @NonNull
            AttestationResolver attestationResolver,
        @NonNull
        Cache<String, Attestation> cache
    ) {
        this.trustResolver = trustResolver;
        this.attestationResolver = attestationResolver;
        this.cache = cache;
    }

    public StandardMetadataService(TrustResolver trustResolver, AttestationResolver attestationResolver) {
        this(
            trustResolver,
            attestationResolver,
            CacheBuilder.newBuilder().build()
        );
    }

    public StandardMetadataService() throws CertificateException {
        this(
            createDefaultTrustResolver(),
            createDefaultMetadataResolver()
        );
    }

    public Attestation getCachedAttestation(String attestationCertificateFingerprint) {
        return cache.getIfPresent(attestationCertificateFingerprint);
    }

    /**
     * Attempt to look up attestation for a chain of certificates
     *
     * <p>
     * If there is a signature path from any trusted certificate to the first
     * certificate in <code>attestationCertificateChain</code>, then the first
     * certificate in <code>attestationCertificateChain</code> is matched
     * against the metadata registry to look up metadata for the device.
     * </p>
     *
     * <p>
     * If the certificate chain is trusted but no metadata exists in the
     * registry, the method returns a trusted attestation populated with
     * information found embedded in the attestation certificate.
     * </p>
     *
     * <p>
     * If there is no signature path from any trusted certificate to the first
     * certificate in <code>attestationCertificateChain</code>, the method
     * returns an untrusted attestation populated with information found
     * embedded in the attestation certificate.
     * </p>
     *
     * <p>
     * If <code>attestationCertificateChain</code> is empty, an untrusted empty
     * attestation is returned.
     * </p>
     *
     * @param attestationCertificateChain a certificate chain, where each
     *          certificate in the list should be signed by the following certificate.
     *
     * @throws CertificateEncodingException if computation of the fingerprint
     * fails for any element of <code>attestationCertificateChain</code> that
     * needs to be inspected
     *
     * @return An attestation as described above.
     */
    @Override
    public Attestation getAttestation(@NonNull List<X509Certificate> attestationCertificateChain) throws CertificateEncodingException {
        if (attestationCertificateChain.isEmpty()) {
            return unknownAttestation;
        }

        X509Certificate attestationCertificate = attestationCertificateChain.get(0);
        List<X509Certificate> certificateChain = attestationCertificateChain.subList(1, attestationCertificateChain.size());

        Optional<X509Certificate> trustAnchor = trustResolver.resolveTrustAnchor(attestationCertificate, certificateChain);

        try {
            final String fingerprint = Hashing.sha1().hashBytes(attestationCertificate.getEncoded()).toString();
            return cache.get(
                fingerprint,
                () ->
                    attestationResolver.resolve(attestationCertificate, trustAnchor)
                        .orElseGet(() -> attestationResolver.untrustedFromCertificate(attestationCertificate))
            );
        } catch (ExecutionException e) {
            throw ExceptionUtil.wrapAndLog(logger, "Failed to look up attestation information for certificate: " + attestationCertificate, e);
        }
    }

}
