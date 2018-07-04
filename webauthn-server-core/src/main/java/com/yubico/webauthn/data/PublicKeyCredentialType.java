package com.yubico.webauthn.data;

import java.util.Optional;
import java.util.stream.Stream;

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
public enum PublicKeyCredentialType {
    PUBLIC_KEY("public-key");

    private final String id;

    PublicKeyCredentialType(String id) {
        this.id = id;
    }

    public static Optional<PublicKeyCredentialType> fromString(String id) {
        return Stream.of(values()).filter(v -> v.id.equals(id)).findAny();
    }
}

