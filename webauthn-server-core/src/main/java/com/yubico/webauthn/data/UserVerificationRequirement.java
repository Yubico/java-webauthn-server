package com.yubico.webauthn.data;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.yubico.webauthn.impl.json.StringIdJsonSerializer;
import com.yubico.webauthn.impl.json.WithStringId;
import lombok.AllArgsConstructor;
import lombok.Getter;


@JsonSerialize(using = StringIdJsonSerializer.class)
@AllArgsConstructor
public enum UserVerificationRequirement implements WithStringId {
    DISCOURAGED("discouraged"),
    PREFERRED("preferred"),
    REQUIRED("required");

    @Getter
    private final String id;

    public static UserVerificationRequirement DEFAULT = PREFERRED;

}

