package com.yubico.webauthn.data;

import java.util.Arrays;
import java.util.Optional;

public enum TokenBindingStatus {

    NOT_SUPPORTED("not-supported"),
    PRESENT("present"),
    SUPPORTED("supported");

    private String jsonValue;

    TokenBindingStatus(String jsonValue) {
        this.jsonValue = jsonValue;
    }

    public static Optional<TokenBindingStatus> fromJson(String value) {
        return Arrays.asList(values()).stream()
            .filter(v -> v.jsonValue.equals(value))
            .findAny();
    }

    public String toJson() {
        return jsonValue;
    }

}
