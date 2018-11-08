/* Copyright 2015 Yubico */

package com.yubico.webauthn.attestation;

import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.hash.Hashing;
import com.yubico.internal.util.ExceptionUtil;
import com.yubico.webauthn.attestation.resolver.SimpleAttestationResolver;
import com.yubico.webauthn.attestation.resolver.SimpleTrustResolver;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ExecutionException;
import lombok.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class StandardMetadataService implements MetadataService {
    private static final Logger logger = LoggerFactory.getLogger(StandardMetadataService.class);

    private final Attestation unknownAttestation = Attestation.builder(false).build();
    private final AttestationResolver attestationResolver;
    private final Cache<String, Attestation> cache;

    private StandardMetadataService(
        @NonNull
        AttestationResolver attestationResolver,
        @NonNull
        Cache<String, Attestation> cache
    ) {
        this.attestationResolver = attestationResolver;
        this.cache = cache;
    }

    public StandardMetadataService(AttestationResolver attestationResolver) {
        this(
            attestationResolver,
            CacheBuilder.newBuilder().build()
        );
    }

    public StandardMetadataService() throws CertificateException {
        this(createDefaultAttestationResolver());
    }

    public static TrustResolver createDefaultTrustResolver() throws CertificateException {
        return SimpleTrustResolver.fromMetadata(Collections.singleton(MetadataObject.readDefault()));
    }

    public static AttestationResolver createDefaultAttestationResolver(TrustResolver trustResolver) throws CertificateException {
        return new SimpleAttestationResolver(
            Collections.singleton(MetadataObject.readDefault()),
            trustResolver
        );
    }

    public static AttestationResolver createDefaultAttestationResolver() throws CertificateException {
        return createDefaultAttestationResolver(createDefaultTrustResolver());
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
     * If the certificate chain is not trusted, the method returns an untrusted
     * attestation populated with transports information found embedded in the
     * attestation certificate.
     * </p>
     *
     * <p>
     * If the certificate chain is empty, an untrusted empty attestation is
     * returned.
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

        try {
            final String fingerprint = Hashing.sha1().hashBytes(attestationCertificate.getEncoded()).toString();
            return cache.get(
                fingerprint,
                () ->
                    attestationResolver.resolve(attestationCertificate, certificateChain)
                        .orElseGet(() -> attestationResolver.untrustedFromCertificate(attestationCertificate))
            );
        } catch (ExecutionException e) {
            throw ExceptionUtil.wrapAndLog(logger, "Failed to look up attestation information for certificate: " + attestationCertificate, e);
        }
    }

}
