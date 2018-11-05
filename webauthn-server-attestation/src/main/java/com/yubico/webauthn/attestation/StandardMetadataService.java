/* Copyright 2015 Yubico */

package com.yubico.webauthn.attestation;

import com.fasterxml.jackson.databind.JsonNode;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Lists;
import com.google.common.collect.Maps;
import com.google.common.hash.Hashing;
import com.google.common.io.Closeables;
import com.yubico.internal.util.ExceptionUtil;
import com.yubico.internal.util.WebAuthnCodecs;
import com.yubico.webauthn.attestation.matcher.ExtensionMatcher;
import com.yubico.webauthn.attestation.matcher.FingerprintMatcher;
import com.yubico.webauthn.attestation.resolver.SimpleMetadataResolver;
import com.yubico.webauthn.attestation.resolver.SimpleTrustResolver;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ExecutionException;
import lombok.NonNull;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class StandardMetadataService implements MetadataService {
    private static final Logger logger = LoggerFactory.getLogger(StandardMetadataService.class);

    private static final String SELECTORS = "selectors";
    private static final String SELECTOR_TYPE = "type";
    private static final String SELECTOR_PARAMETERS = "parameters";

    private static final String TRANSPORTS = "transports";
    private static final String TRANSPORTS_EXT_OID = "1.3.6.1.4.1.45724.2.1.1";

    private static final Map<String, DeviceMatcher> DEFAULT_DEVICE_MATCHERS = ImmutableMap.of(
            ExtensionMatcher.SELECTOR_TYPE, new ExtensionMatcher(),
            FingerprintMatcher.SELECTOR_TYPE, new FingerprintMatcher()
    );

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

    public static MetadataResolver createDefaultMetadataResolver() throws CertificateException {
        return new SimpleMetadataResolver(Collections.singleton(readDefaultMetadata()));
    }

    private static StandardMetadataService usingMetadata(Collection<MetadataObject> metadata) throws CertificateException {
        return new StandardMetadataService(
            SimpleTrustResolver.fromMetadata(metadata),
            new SimpleMetadataResolver(metadata)
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
    private final MetadataResolver metadataResolver;
    private final Map<String, DeviceMatcher> matchers;
    private final Cache<String, Attestation> cache;

    private StandardMetadataService(
        @NonNull
        TrustResolver trustResolver,
        @NonNull
        MetadataResolver metadataResolver,
        @NonNull
        Cache<String, Attestation> cache,
        @NonNull
        Map<String, ? extends DeviceMatcher> matchers
    ) {
        this.trustResolver = trustResolver;
        this.metadataResolver = metadataResolver;
        this.cache = cache;
        this.matchers = Collections.unmodifiableMap(matchers);
    }

    public StandardMetadataService(TrustResolver trustResolver, MetadataResolver metadataResolver) {
        this(
            trustResolver,
            metadataResolver,
            CacheBuilder.newBuilder().build(),
            DEFAULT_DEVICE_MATCHERS
        );
    }

    public StandardMetadataService() throws CertificateException {
        this(
            createDefaultTrustResolver(),
            createDefaultMetadataResolver()
        );
    }

    private boolean deviceMatches(
        JsonNode selectors,
        @NonNull X509Certificate attestationCertificate
    ) {
        if (selectors == null || selectors.isNull()) {
            return true;
        } else {
            for (JsonNode selector : selectors) {
                DeviceMatcher matcher = matchers.get(selector.get(SELECTOR_TYPE).asText());
                if (matcher != null && matcher.matches(attestationCertificate, selector.get(SELECTOR_PARAMETERS))) {
                    return true;
                }
            }
            return false;
        }
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
            return cache.get(fingerprint, () -> lookupMetadata(attestationCertificate, trustAnchor));
        } catch (ExecutionException e) {
            throw ExceptionUtil.wrapAndLog(logger, "Failed to look up attestation information for certificate: " + attestationCertificate, e);
        }
    }

    private Attestation lookupMetadata(X509Certificate attestationCertificate, Optional<X509Certificate> trustAnchor) {
        final int certTransports = get_transports(attestationCertificate.getExtensionValue(TRANSPORTS_EXT_OID));

        return trustAnchor.flatMap(metadataResolver::resolve).map(metadata -> {
            Map<String, String> vendorProperties;
            Map<String, String> deviceProperties = null;
            String identifier;
            int metadataTransports = 0;

            identifier = metadata.getIdentifier();
            vendorProperties = Maps.filterValues(metadata.getVendorInfo(), Objects::nonNull);
            for (JsonNode device : metadata.getDevices()) {
                if (deviceMatches(device.get(SELECTORS), attestationCertificate)) {
                    JsonNode transportNode = device.get(TRANSPORTS);
                    if(transportNode != null) {
                        metadataTransports |= transportNode.asInt(0);
                    }
                    ImmutableMap.Builder<String, String> devicePropertiesBuilder = ImmutableMap.builder();
                    for (Map.Entry<String, JsonNode> deviceEntry : Lists.newArrayList(device.fields())) {
                        JsonNode value = deviceEntry.getValue();
                        if (value.isTextual()) {
                            devicePropertiesBuilder.put(deviceEntry.getKey(), value.asText());
                        }
                    }
                    deviceProperties = devicePropertiesBuilder.build();
                    break;
                }
            }

            return Attestation.builder(true)
                .metadataIdentifier(Optional.ofNullable(identifier))
                .vendorProperties(Optional.of(vendorProperties))
                .deviceProperties(Optional.ofNullable(deviceProperties))
                .transports(Optional.of(Transport.fromInt(certTransports | metadataTransports)))
                .build();
        }).orElseGet(() ->
            Attestation.builder(false)
                .transports(Optional.of(Transport.fromInt(certTransports)))
                .build()
        );
    }

    private int get_transports(byte[] extensionValue) {
        if(extensionValue == null) {
            return 0;
        }

        // Mask out unused bits (shouldn't be needed as they should already be 0).
        int unusedBitMask = 0xff;
        for(int i=0; i < extensionValue[3]; i++) {
            unusedBitMask <<= 1;
        }
        extensionValue[extensionValue.length-1] &= unusedBitMask;

        int transports = 0;
        for(int i=extensionValue.length - 1; i >= 5; i--) {
            byte b = extensionValue[i];
            for(int bi=0; bi < 8; bi++) {
                transports = (transports << 1) | (b & 1);
                b >>= 1;
            }
        }

        return transports;
    }
}
