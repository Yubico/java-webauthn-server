package com.yubico.webauthn.data;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.yubico.internal.util.json.JsonStringSerializable;
import com.yubico.internal.util.json.JsonStringSerializer;
import lombok.AllArgsConstructor;
import lombok.NonNull;


@JsonSerialize(using = JsonStringSerializer.class)
@AllArgsConstructor
public enum UserVerificationRequirement implements JsonStringSerializable {
    DISCOURAGED("discouraged"),
    PREFERRED("preferred"),
    REQUIRED("required");

    @NonNull
    private final String id;

    public static UserVerificationRequirement DEFAULT = PREFERRED;

    @Override
    public String toJsonString() {
        return id;
    }

}

