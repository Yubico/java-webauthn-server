package com.yubico.fido.metadata;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

class JacksonCodecs {

  static ObjectMapper jsonWithDefaultEnums() {
    return com.yubico.internal.util.JacksonCodecs.json()
        .configure(DeserializationFeature.READ_UNKNOWN_ENUM_VALUES_USING_DEFAULT_VALUE, true);
  }
}
