package com.yubico.webauthn.data;

import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.yubico.webauthn.impl.json.LongIdJsonSerializer;
import com.yubico.webauthn.impl.json.WithLongId;
import lombok.Value;

/**
 * A number identifying a cryptographic algorithm. The algorithm identifiers
 * SHOULD be values registered in the IANA COSE Algorithms registry, for
 * instance, -7 for "ES256" and -257 for "RS256".
 */
@JsonSerialize(using = LongIdJsonSerializer.class)
@Value
public class COSEAlgorithmIdentifier implements WithLongId {

    private final long id;

}
