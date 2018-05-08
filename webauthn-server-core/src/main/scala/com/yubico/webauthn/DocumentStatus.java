package com.yubico.webauthn;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import java.io.IOException;

@JsonSerialize(using = DocumentStatus.JsonSerializer.class)
public enum DocumentStatus {
    WORKING_DRAFT("working-draft"),
    CANDIDATE_RECOMMENDATION("candidate-recommendation");

    private final String name;

    DocumentStatus(String name) {
        this.name = name;
    }

    static class JsonSerializer extends com.fasterxml.jackson.databind.JsonSerializer<DocumentStatus> {
        @Override
        public void serialize(DocumentStatus documentStatus, JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws IOException {
            jsonGenerator.writeString(documentStatus.name);
        }
    }

}
