package com.yubico.webauthn.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.yubico.webauthn.impl.json.JsonStringSerializable;
import com.yubico.webauthn.impl.json.JsonStringSerializer;
import java.util.Optional;
import java.util.stream.Stream;
import lombok.AllArgsConstructor;
import lombok.NonNull;

/**
  * Defines the valid credential types.
  *
  * It is an extensions point; values may be added to it in the future, as more
  * credential types are defined. The values of this enumeration are used for
  * versioning the Authentication Assertion and attestation structures
  * according to the type of the authenticator.
  *
  * Currently one credential type is defined, namely [[PublicKey]].
  */
@JsonSerialize(using = JsonStringSerializer.class)
@AllArgsConstructor
public enum PublicKeyCredentialType implements JsonStringSerializable {
    PUBLIC_KEY("public-key");

    @NonNull
    private final String id;

    public static Optional<PublicKeyCredentialType> fromString(@NonNull String id) {
        return Stream.of(values()).filter(v -> v.id.equals(id)).findAny();
    }

    @JsonCreator
    private static PublicKeyCredentialType fromJsonString(@NonNull String id) {
        return fromString(id).orElseThrow(() -> new IllegalArgumentException(String.format(
            "Unknown %s value: %s", PublicKeyCredentialType.class.getSimpleName(), id
        )));
    }

    @Override
    public String toJsonString() {
        return id;
    }

}

