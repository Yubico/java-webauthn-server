package com.yubico.u2f.data;

import com.google.gson.Gson;

public abstract class DataObject {
  protected static final Gson GSON = new Gson();

  public String toJson() {
    return GSON.toJson(this);
  }
}
