package com.yubico.webauthn.data;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import java.io.IOException;


@JsonSerialize(using = UserVerificationRequirement.JsonSerializer.class)
public enum UserVerificationRequirement {
    DISCOURAGED("discouraged"),
    PREFERRED("preferred"),
    REQUIRED("required");

    private final String id;

    UserVerificationRequirement(String id) {
        this.id = id;
    }

    public static UserVerificationRequirement DEFAULT = PREFERRED;

    static class JsonSerializer extends com.fasterxml.jackson.databind.JsonSerializer<UserVerificationRequirement> {
        @Override
        public void serialize(UserVerificationRequirement t, JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws IOException {
            jsonGenerator.writeString(t.id);
        }
    }

}

