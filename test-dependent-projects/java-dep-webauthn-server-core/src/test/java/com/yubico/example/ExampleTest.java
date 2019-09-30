package com.yubico.example;

import org.junit.Test;

import static org.junit.Assert.assertNotNull;

public class ExampleTest {

    @Test
    public void rpIsNotNull() {
        assertNotNull(new Example().getRp());
    }

}
