package com.yubico.webauthn.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.yubico.internal.util.json.JsonStringSerializable;
import com.yubico.internal.util.json.JsonStringSerializer;
import java.util.Optional;
import java.util.stream.Stream;
import lombok.AllArgsConstructor;
import lombok.NonNull;

@JsonSerialize(using = JsonStringSerializer.class)
@AllArgsConstructor
public enum RecoveryExtensionAction implements JsonStringSerializable {

    STATE("state"),
    GENERATE("generate"),
    RECOVER("recover");

    @NonNull
    private final String id;

    static Optional<RecoveryExtensionAction> fromString(@NonNull String id) {
        return Stream.of(values()).filter(v -> v.id.equals(id)).findAny();
    }

    @JsonCreator
    private static RecoveryExtensionAction fromJsonString(@NonNull String id) {
        return fromString(id).orElseThrow(() -> new IllegalArgumentException(String.format(
            "Unknown %s value: %s", RecoveryExtensionAction.class.getSimpleName(), id
        )));
    }

    @Override
    public String toJsonString() {
        return id;
    }

}
