/* Copyright 2015 Yubico */

package com.yubico.u2f.attestation;

import com.google.common.collect.ImmutableMap;
import com.google.common.collect.ImmutableSet;
import com.google.common.collect.Sets;

import java.io.Serializable;
import java.util.EnumSet;
import java.util.Map;
import java.util.Set;
import lombok.Getter;

@Getter
public class Attestation implements Serializable {
    private final String metadataIdentifier;
    private final Map<String, String> vendorProperties;
    private final Map<String, String> deviceProperties;
    private final Set<Transport> transports;

    private Attestation() {
        metadataIdentifier = null;
        vendorProperties = null;
        deviceProperties = null;
        transports = Sets.immutableEnumSet(null);
    }

    public Attestation(String metadataIdentifier, Map<String, String> vendorProperties, Map<String, String> deviceProperties, Set<Transport> transports) {
        this.metadataIdentifier = metadataIdentifier;
        this.vendorProperties = vendorProperties == null ? ImmutableMap.<String, String>of() : ImmutableMap.copyOf(vendorProperties);
        this.deviceProperties = deviceProperties == null ? ImmutableMap.<String, String>of() : ImmutableMap.copyOf(deviceProperties);
        this.transports = Sets.immutableEnumSet(transports == null ? ImmutableSet.<Transport>of() : transports);
    }

    public boolean isTrusted() {
        return metadataIdentifier != null;
    }

}
