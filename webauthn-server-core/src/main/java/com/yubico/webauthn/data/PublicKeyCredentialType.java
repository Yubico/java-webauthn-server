package com.yubico.webauthn.data;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.yubico.webauthn.impl.json.StringIdJsonSerializer;
import com.yubico.webauthn.impl.json.WithStringId;
import java.util.Optional;
import java.util.stream.Stream;
import lombok.AllArgsConstructor;
import lombok.Getter;

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
@JsonSerialize(using = StringIdJsonSerializer.class)
@AllArgsConstructor
public enum PublicKeyCredentialType implements WithStringId {
    PUBLIC_KEY("public-key");

    @Getter
    private final String id;

    public static Optional<PublicKeyCredentialType> fromString(String id) {
        return Stream.of(values()).filter(v -> v.id.equals(id)).findAny();
    }

}

