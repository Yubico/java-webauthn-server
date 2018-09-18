package com.yubico.webauthn.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.yubico.internal.util.json.JsonStringSerializable;
import com.yubico.internal.util.json.JsonStringSerializer;
import java.util.Arrays;
import java.util.Optional;
import lombok.AllArgsConstructor;
import lombok.NonNull;

@AllArgsConstructor
@JsonSerialize(using = JsonStringSerializer.class)
public enum TokenBindingStatus implements JsonStringSerializable {

    NOT_SUPPORTED("not-supported"),
    PRESENT("present"),
    SUPPORTED("supported");

    @NonNull
    private final String id;

    public static Optional<TokenBindingStatus> fromString(@NonNull String value) {
        return Arrays.stream(values())
            .filter(v -> v.id.equals(value))
            .findAny();
    }

    @JsonCreator
    public static TokenBindingStatus fromJsonString(@NonNull String id) {
        return fromString(id).orElseThrow(() -> new IllegalArgumentException(String.format(
            "Unknown %s value: %s", TokenBindingStatus.class.getSimpleName(), id
        )));
    }

    @Override
    public String toJsonString() {
        return id;
    }

}
