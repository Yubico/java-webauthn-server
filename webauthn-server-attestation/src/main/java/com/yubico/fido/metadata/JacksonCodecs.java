package com.yubico.fido.metadata;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

class JacksonCodecs {

  static ObjectMapper json() {
    return com.yubico.internal.util.JacksonCodecs.json()
        .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
  }

  static ObjectMapper jsonWithDefaultEnums() {
    return json()
        .configure(DeserializationFeature.READ_UNKNOWN_ENUM_VALUES_USING_DEFAULT_VALUE, true);
  }
}
