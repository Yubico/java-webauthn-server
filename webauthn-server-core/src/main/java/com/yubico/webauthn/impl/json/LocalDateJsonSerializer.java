package com.yubico.webauthn.impl.json;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.JsonSerializer;
import com.fasterxml.jackson.databind.SerializerProvider;
import java.io.IOException;
import java.time.LocalDate;


public class LocalDateJsonSerializer extends JsonSerializer<LocalDate> {

    @Override
    public void serialize(LocalDate t, JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws IOException {
        jsonGenerator.writeString(t.toString());
    }

}
