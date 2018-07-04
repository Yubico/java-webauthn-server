package com.yubico.webauthn.data;

import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import java.io.IOException;
import lombok.Value;

/**
 * A number identifying a cryptographic algorithm. The algorithm identifiers
 * SHOULD be values registered in the IANA COSE Algorithms registry, for
 * instance, -7 for "ES256" and -257 for "RS256".
 */
@JsonSerialize(using = COSEAlgorithmIdentifier.JsonSerializer.class)
@Value
public class COSEAlgorithmIdentifier {

    public final long value;

    @java.beans.ConstructorProperties({"value"})
    public COSEAlgorithmIdentifier(long value) {
        this.value = value;
    }

    static class JsonSerializer extends com.fasterxml.jackson.databind.JsonSerializer<COSEAlgorithmIdentifier> {
        @Override
        public void serialize(COSEAlgorithmIdentifier coseAlgorithmIdentifier, JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws IOException {
            jsonGenerator.writeNumber(coseAlgorithmIdentifier.value);
        }
    }
}
