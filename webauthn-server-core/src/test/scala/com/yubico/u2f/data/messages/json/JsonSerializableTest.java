package com.yubico.u2f.data.messages.json;

import com.fasterxml.jackson.annotation.JsonProperty;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class JsonSerializableTest {

    private static class Thing extends JsonSerializable {
        @JsonProperty final String foo;
        private Thing(@JsonProperty("foo") String foo) {
            this.foo = foo;
        }
    }

    @Test
    public void toStringReturnsJson() {
        assertEquals("{\"foo\":\"bar\"}", new Thing("bar").toString());
    }
}
