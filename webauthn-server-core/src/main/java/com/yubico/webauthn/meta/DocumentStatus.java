package com.yubico.webauthn.meta;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.yubico.util.json.JsonStringSerializable;
import com.yubico.util.json.JsonStringSerializer;
import lombok.AllArgsConstructor;

@JsonSerialize(using = JsonStringSerializer.class)
@AllArgsConstructor
public enum DocumentStatus implements JsonStringSerializable {
    WORKING_DRAFT("working-draft"),
    CANDIDATE_RECOMMENDATION("candidate-recommendation");

    private final String id;

    @Override
    public String toJsonString() {
        return id;
    }

}
