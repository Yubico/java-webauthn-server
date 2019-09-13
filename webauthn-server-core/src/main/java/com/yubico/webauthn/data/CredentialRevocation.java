package com.yubico.webauthn.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;

@Value
@Builder(toBuilder = true)
public final class CredentialRevocation {

    @NonNull
    private final ByteArray revokedCredentialId;

    @NonNull
    private final ByteArray recoveryCredentialId;

    @NonNull
    private final ByteArray newCredentialId;

    @JsonCreator
    private CredentialRevocation(
        @NonNull @JsonProperty("revokedCredentialId") ByteArray revokedCredentialId,
        @NonNull @JsonProperty("recoveryCredentialId") ByteArray recoveryCredentialId,
        @NonNull @JsonProperty("newCredentialId") ByteArray newCredentialId
    ) {
        this.revokedCredentialId = revokedCredentialId;
        this.recoveryCredentialId = recoveryCredentialId;
        this.newCredentialId = newCredentialId;
    }

}
