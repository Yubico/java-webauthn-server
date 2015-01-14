package com.yubico.u2f.data.messages.json;

import com.google.gson.Gson;

public abstract class JsonSerializable {
    protected static final Gson GSON = new Gson();

    public String toJson() {
        return GSON.toJson(this);
    }

    public static <T extends JsonSerializable> T fromJson(String json, Class<T> cls) {
        return GSON.fromJson(json, cls);
    }
}
