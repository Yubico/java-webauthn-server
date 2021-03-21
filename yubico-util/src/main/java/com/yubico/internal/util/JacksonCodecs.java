package com.yubico.internal.util;

import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.core.Base64Variants;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.fasterxml.jackson.datatype.jdk8.Jdk8Module;
import com.upokecenter.cbor.CBORObject;
import java.io.IOException;

public class JacksonCodecs {

  public static ObjectMapper cbor() {
    return new ObjectMapper(new CBORFactory()).setBase64Variant(Base64Variants.MODIFIED_FOR_URL);
  }

  public static ObjectMapper json() {
    return new ObjectMapper()
        .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, true)
        .configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false)
        .setSerializationInclusion(Include.NON_ABSENT)
        .setBase64Variant(Base64Variants.MODIFIED_FOR_URL)
        .registerModule(new Jdk8Module());
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
