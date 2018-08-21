package com.yubico.webauthn.data;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.yubico.webauthn.impl.json.JsonLongSerializable;
import com.yubico.webauthn.impl.json.JsonLongSerializer;
import lombok.Value;

/**
 * A number identifying a cryptographic algorithm. The algorithm identifiers
 * SHOULD be values registered in the IANA COSE Algorithms registry, for
 * instance, -7 for "ES256" and -257 for "RS256".
 */
@JsonSerialize(using = JsonLongSerializer.class)
@Value
public class COSEAlgorithmIdentifier implements JsonLongSerializable {

    private final long id;

    @Override
    public long toJsonNumber() {
        return id;
    }

    public static final COSEAlgorithmIdentifier ES256 = new COSEAlgorithmIdentifier(-7);
    public static final COSEAlgorithmIdentifier RS256 = new COSEAlgorithmIdentifier(-257);

}
