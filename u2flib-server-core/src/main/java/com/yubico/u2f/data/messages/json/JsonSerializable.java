package com.yubico.u2f.data.messages.json;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonValue;
import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.yubico.u2f.exceptions.U2fBadInputException;

import java.io.IOException;

@JsonIgnoreProperties(ignoreUnknown = true)
public abstract class JsonSerializable {
    protected static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    public String toJson() {
        try {
            return OBJECT_MAPPER.writeValueAsString(this);
        } catch (IOException e) {
            throw new IllegalArgumentException(e);
        }
    }

    public static <T extends JsonSerializable> T fromJson(String json, Class<T> cls) throws U2fBadInputException {
        try {
            return OBJECT_MAPPER.readValue(json, cls);
        } catch (JsonMappingException e) {
            throw new U2fBadInputException("Invalid JSON data", e);
        } catch (JsonParseException e) {
            throw new U2fBadInputException("Invalid JSON data", e);
        } catch (IOException e) {
            throw new U2fBadInputException("Invalid JSON data", e);
        }
    }
}
