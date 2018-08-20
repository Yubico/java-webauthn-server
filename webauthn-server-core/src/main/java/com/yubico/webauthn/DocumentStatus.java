package com.yubico.webauthn;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.yubico.webauthn.impl.json.StringIdJsonSerializer;
import com.yubico.webauthn.impl.json.WithStringId;
import lombok.AllArgsConstructor;
import lombok.Getter;

@JsonSerialize(using = StringIdJsonSerializer.class)
@AllArgsConstructor
public enum DocumentStatus implements WithStringId {
    WORKING_DRAFT("working-draft"),
    CANDIDATE_RECOMMENDATION("candidate-recommendation");

    @Getter
    private final String id;

}
