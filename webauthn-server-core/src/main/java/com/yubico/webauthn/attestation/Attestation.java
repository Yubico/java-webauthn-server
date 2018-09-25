/* Copyright 2015 Yubico */

package com.yubico.webauthn.attestation;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.io.Serializable;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;

@Value
@Builder
public class Attestation implements Serializable {

    private final boolean trusted;

    @NonNull
    @Builder.Default
    private final Optional<String> metadataIdentifier = Optional.empty();

    @NonNull
    @Builder.Default
    private final Optional<Map<String, String>> vendorProperties = Optional.empty();

    @NonNull
    @Builder.Default
    private final Optional<Map<String, String>> deviceProperties = Optional.empty();

    @NonNull
    @Builder.Default
    private final Optional<Set<Transport>> transports = Optional.empty();

    @JsonCreator
    private Attestation(
        @JsonProperty("trusted") boolean trusted,
        @NonNull @JsonProperty("metadataIdentifier") Optional<String> metadataIdentifier,
        @NonNull @JsonProperty("vendorProperties") Optional<Map<String, String>> vendorProperties,
        @NonNull @JsonProperty("deviceProperties") Optional<Map<String, String>> deviceProperties,
        @NonNull @JsonProperty("transports") Optional<Set<Transport>> transports
    ) {
        this.trusted = trusted;
        this.metadataIdentifier = metadataIdentifier;
        this.vendorProperties = vendorProperties;
        this.deviceProperties = deviceProperties;
        this.transports = transports.map(TreeSet::new);
    }

    public static AttestationBuilder builder(boolean trusted) {
        return new AttestationBuilder().trusted(trusted);
    }

}
