package com.yubico.u2f.attestation;

import com.google.common.base.Objects;
import com.google.common.collect.ImmutableMap;

import java.io.Serializable;
import java.util.Map;

/**
 * Created by dain on 12/5/14.
 */
public class Attestation implements Serializable {
    private final String metadataIdentifier;
    private final Map<String, String> vendorProperties;
    private final Map<String, String> deviceProperties;

    private Attestation() {
        metadataIdentifier = null;
        vendorProperties = null;
        deviceProperties = null;
    }

    public Attestation(String metadataIdentifier, Map<String, String> vendorProperties, Map<String, String> deviceProperties) {
        this.metadataIdentifier = metadataIdentifier;
        this.vendorProperties = vendorProperties == null ? ImmutableMap.<String, String>of() : ImmutableMap.copyOf(vendorProperties);
        this.deviceProperties = deviceProperties == null ? ImmutableMap.<String, String>of() : ImmutableMap.copyOf(deviceProperties);
    }

    public boolean isTrusted() {
        return metadataIdentifier != null;
    }

    public String getMetadataIdentifier() {
        return metadataIdentifier;
    }

    public Map<String, String> getVendorProperties() {
        return vendorProperties;
    }

    public Map<String, String> getDeviceProperties() {
        return deviceProperties;
    }
}
