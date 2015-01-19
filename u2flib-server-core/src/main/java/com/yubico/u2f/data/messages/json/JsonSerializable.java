package com.yubico.u2f.data.messages.json;

import com.google.gson.Gson;
import com.google.gson.JsonSyntaxException;
import com.yubico.u2f.exceptions.U2fBadInputException;

public abstract class JsonSerializable {
    protected static final Gson GSON = new Gson();

    public String toJson() {
        return GSON.toJson(this);
    }

    public static <T extends JsonSerializable> T fromJson(String json, Class<T> cls) throws U2fBadInputException {
        try {
            return GSON.fromJson(json, cls);
        } catch (JsonSyntaxException e) {
            throw new U2fBadInputException("Invalid JSON data", e);
        }
    }
}
