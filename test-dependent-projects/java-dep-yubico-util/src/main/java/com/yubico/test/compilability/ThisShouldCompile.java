package com.yubico.test.compilability;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.yubico.internal.util.JacksonCodecs;

public class ThisShouldCompile {

    public String getEncodedValue() throws JsonProcessingException {
        return JacksonCodecs.json().writeValueAsString("hej");
    }

}
