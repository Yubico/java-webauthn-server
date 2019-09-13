package com.yubico.webauthn.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Set;
import java.util.TreeSet;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;

@Value
@Builder(toBuilder = true)
public class RecoveryCredentialsState {

    @NonNull
    private final ByteArray mainCredentialId;

    private final int state;

    private final Set<RecoveryCredential> recoveryCredentials;

    @JsonCreator
    private RecoveryCredentialsState(
        @NonNull @JsonProperty("mainCredentialId") ByteArray mainCredentialId,
        @JsonProperty("state") int state,
        @JsonProperty("recoveryCredentials") Set<RecoveryCredential> recoveryCredentials
    ) {
        this.mainCredentialId = mainCredentialId;
        this.state = state;
        this.recoveryCredentials = new TreeSet<>(recoveryCredentials);
    }
}
