package com.yubico.example;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.yubico.internal.util.JacksonCodecs;

public class Example {

    public String getEncodedValue() throws JsonProcessingException {
        return JacksonCodecs.json().writeValueAsString("hej");
    }

}
