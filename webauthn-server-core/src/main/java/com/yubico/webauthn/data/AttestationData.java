package com.yubico.webauthn.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;

@Value
@Builder
public class AttestationData {

    /**
     * The AAGUID of the authenticator.
     */
    @NonNull
    private final ByteArray aaguid;

    /**
     * The ID of the attested credential.
     */
    @NonNull
    private final ByteArray credentialId;

    /**
     * The ''credential public key'' encoded in COSE_Key format.
     *
     * @todo verify requirements https://www.w3.org/TR/webauthn/#sec-attestation-data
     */
    @NonNull
    private final ByteArray credentialPublicKey;

    @JsonCreator
    private AttestationData(
        @NonNull @JsonProperty("aaguid") ByteArray aaguid,
        @NonNull @JsonProperty("credentialId") ByteArray credentialId,
        @NonNull @JsonProperty("credentialPublicKey") ByteArray credentialPublicKey
    ) {
        this.aaguid = aaguid;
        this.credentialId = credentialId;
        this.credentialPublicKey = credentialPublicKey;
    }

}
