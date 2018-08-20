package com.yubico.webauthn.impl.json;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import java.io.IOException;

public class StringIdJsonSerializer<T extends WithStringId> extends JsonSerializer<T> {

    @Override
    public void serialize(T t, JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws IOException {
        jsonGenerator.writeString(t.getId());
    }

}
