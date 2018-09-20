/* Copyright 2015 Yubico */

package com.yubico.attestation;

import java.io.Serializable;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;

@Value
@AllArgsConstructor(access = AccessLevel.PRIVATE)
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

    public static AttestationBuilder builder(boolean trusted) {
        return new AttestationBuilder().trusted(trusted);
    }

}
