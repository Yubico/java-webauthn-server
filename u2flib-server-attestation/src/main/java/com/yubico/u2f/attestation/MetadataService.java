/* Copyright 2015 Yubico */

package com.yubico.u2f.attestation;

import com.google.common.base.Charsets;
import com.google.common.base.Predicates;
import com.google.common.cache.Cache;
import com.google.common.cache.CacheBuilder;
import com.google.common.collect.ImmutableMap;
import com.google.common.collect.Maps;
import com.google.common.hash.Hashing;
import com.google.common.io.CharStreams;
import com.google.common.io.Closeables;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.yubico.u2f.attestation.matchers.ExtensionMatcher;
import com.yubico.u2f.attestation.resolvers.SimpleResolver;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;

public class MetadataService {
    public static final String SELECTORS = "selectors";
    private static final String SELECTOR_TYPE = "type";
    private static final String SELECTOR_PARAMETERS = "parameters";

    public static final Map<String, DeviceMatcher> DEFAULT_DEVICE_MATCHERS = ImmutableMap.of(
            ExtensionMatcher.EXTENSION_TYPE, (DeviceMatcher) new ExtensionMatcher()
    );

    private static MetadataResolver createDefaultMetadataResolver() {
        SimpleResolver resolver = new SimpleResolver();
        InputStream is = null;
        try {
            is = MetadataService.class.getResourceAsStream("/metadata.json");
            resolver.addMetadata(CharStreams.toString(new InputStreamReader(is, Charsets.UTF_8)));
        } catch (IOException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } finally {
            Closeables.closeQuietly(is);
        }
        return resolver;
    }

    private final Attestation unknownAttestation = new Attestation(null, null, null);
    private final MetadataResolver resolver;
    private final Map<String, DeviceMatcher> matchers = new HashMap<String, DeviceMatcher>();
    private final Cache<String, Attestation> cache;

    public MetadataService(MetadataResolver resolver, Cache<String, Attestation> cache, Map<String, ? extends DeviceMatcher> matchers) {
        this.resolver = resolver != null ? resolver : createDefaultMetadataResolver();
        this.cache = cache != null ? cache : CacheBuilder.newBuilder().<String, Attestation>build();
        if (matchers == null) {
            matchers = DEFAULT_DEVICE_MATCHERS;
        }
        this.matchers.putAll(matchers);
    }

    public MetadataService() {
        this(null, null, null);
    }

    public MetadataService(MetadataResolver resolver) {
        this(resolver, null, null);
    }

    public MetadataService(MetadataResolver resolver, Map<String, ? extends DeviceMatcher> matchers) {
        this(resolver, null, matchers);
    }

    public MetadataService(MetadataResolver resolver, Cache<String, Attestation> cache) {
        this(resolver, cache, null);
    }

    public void registerDeviceMatcher(String matcherType, DeviceMatcher matcher) {
        matchers.put(matcherType, matcher);
    }

    private boolean deviceMatches(JsonElement selectors, X509Certificate attestationCertificate) {
        if (selectors != null && !selectors.isJsonNull()) {
            for (JsonElement selectorElement : selectors.getAsJsonArray()) {
                JsonObject selector = selectorElement.getAsJsonObject();
                DeviceMatcher matcher = matchers.get(selector.get(SELECTOR_TYPE).getAsString());
                if (matcher != null && matcher.matches(attestationCertificate, selector.get(SELECTOR_PARAMETERS))) {
                    return true;
                }
            }
            return false;
        }
        return true; //Match if selectors is null or missing.
    }

    public Attestation getCachedAttestation(String attestationCertificateFingerprint) {
        return cache.getIfPresent(attestationCertificateFingerprint);
    }

    public Attestation getAttestation(final X509Certificate attestationCertificate) {
        try {
            String fingerprint = Hashing.sha1().hashBytes(attestationCertificate.getEncoded()).toString();
            return cache.get(fingerprint, new Callable<Attestation>() {
                @Override
                public Attestation call() throws Exception {
                    return lookupAttestation(attestationCertificate);
                }
            });
        } catch (ExecutionException e) {
            return unknownAttestation;
        } catch (CertificateEncodingException e) {
            return unknownAttestation;
        }
    }

    private Attestation lookupAttestation(X509Certificate attestationCertificate) {
        MetadataObject metadata = resolver.resolve(attestationCertificate);
        if (metadata != null) {
            Map<String, String> vendorProperties = Maps.filterValues(metadata.getVendorInfo(), Predicates.notNull());
            Map<String, String> deviceProperties = null;
            for (JsonObject device : metadata.getDevices()) {
                if (deviceMatches(device.get(SELECTORS), attestationCertificate)) {
                    ImmutableMap.Builder<String, String> devicePropertiesBuilder = ImmutableMap.builder();
                    for (Map.Entry<String, JsonElement> deviceEntry : device.entrySet()) {
                        JsonElement value = deviceEntry.getValue();
                        if (value.isJsonPrimitive() && value.getAsJsonPrimitive().isString()) {
                            devicePropertiesBuilder.put(deviceEntry.getKey(), value.getAsString());
                        }
                    }
                    deviceProperties = devicePropertiesBuilder.build();
                    break;
                }
            }
            return new Attestation(metadata.getIdentifier(), vendorProperties, deviceProperties);
        }

        return unknownAttestation;
    }
}
