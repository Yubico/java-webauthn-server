package com.yubico.internal.util;

import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.core.Base64Variants;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.upokecenter.cbor.CBORObject;
import java.io.IOException;

public class JacksonCodecs {

  public static ObjectMapper cbor() {
    return new ObjectMapper(new CBORFactory()).setBase64Variant(Base64Variants.MODIFIED_FOR_URL);
  }

  public static ObjectMapper json() {
    return JsonMapper.builder()
        .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true)
        .configure(MapperFeature.PROPAGATE_TRANSIENT_MARKER, true)
        .serializationInclusion(Include.NON_ABSENT)
        .defaultBase64Variant(Base64Variants.MODIFIED_FOR_URL)
        .addModule(new Jdk8Module())
        .addModule(new JavaTimeModule())
        .build();
  }

  public static CBORObject deepCopy(CBORObject a) {
    return CBORObject.DecodeFromBytes(a.EncodeToBytes());
  }

  public static ObjectNode deepCopy(ObjectNode a) {
    try {
      return (ObjectNode) json().readTree(json().writeValueAsString(a));
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }
}
