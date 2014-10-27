package com.yubico.u2f.data.messages.json;

import com.google.gson.Gson;

public abstract class JsonObject {
  protected static final Gson GSON = new Gson();

  public String toJson() {
    return GSON.toJson(this);
  }
}
