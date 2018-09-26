package com.yubico.webauthn.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.yubico.internal.util.json.JsonLongSerializable;
import com.yubico.internal.util.json.JsonLongSerializer;
import java.util.Optional;
import java.util.stream.Stream;
import lombok.Getter;

/**
 * A number identifying a cryptographic algorithm. The algorithm identifiers
 * SHOULD be values registered in the IANA COSE Algorithms registry, for
 * instance, -7 for "ES256" and -257 for "RS256".
 */
@JsonSerialize(using = JsonLongSerializer.class)
public enum COSEAlgorithmIdentifier implements JsonLongSerializable {
    ES256(-7),
    RS256(-257);

    @Getter
    private final long id;

    COSEAlgorithmIdentifier(long id) {
        this.id = id;
    }

    public static Optional<COSEAlgorithmIdentifier> fromId(long id) {
        return Stream.of(values()).filter(v -> v.id == id).findAny();
    }

    @JsonCreator
    private static COSEAlgorithmIdentifier fromJson(long id) {
        return fromId(id).orElseThrow(() -> new IllegalArgumentException("Unknown COSE algorithm identifier: " + id));
    }

    @Override
    public long toJsonNumber() {
        return id;
    }

}
