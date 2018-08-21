package com.yubico.webauthn.data;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.yubico.webauthn.impl.json.JsonStringSerializer;
import com.yubico.webauthn.impl.json.JsonStringSerializable;
import lombok.AllArgsConstructor;


@JsonSerialize(using = JsonStringSerializer.class)
@AllArgsConstructor
public enum UserVerificationRequirement implements JsonStringSerializable {
    DISCOURAGED("discouraged"),
    PREFERRED("preferred"),
    REQUIRED("required");

    private final String id;

    public static UserVerificationRequirement DEFAULT = PREFERRED;

    @Override
    public String toJsonString() {
        return id;
    }

}

