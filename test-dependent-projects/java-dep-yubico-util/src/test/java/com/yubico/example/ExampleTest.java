package com.yubico.example;

import com.fasterxml.jackson.core.JsonProcessingException;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class ExampleTest {

    @Test
    public void stringIsNotNull() throws JsonProcessingException {
        assertEquals("\"hej\"", new Example().getEncodedValue());
    }

}
