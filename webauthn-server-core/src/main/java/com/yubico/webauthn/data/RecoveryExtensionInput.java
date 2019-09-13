package com.yubico.webauthn.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.List;
import java.util.Optional;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;

@Value
@Builder(toBuilder = true)
public class RecoveryExtensionInput {

    @NonNull
    private final RecoveryExtensionAction action;

    private final Optional<List<PublicKeyCredentialDescriptor>> allowCredentials;

    @JsonCreator
    private RecoveryExtensionInput(
        @NonNull @JsonProperty("action") RecoveryExtensionAction action,
        @JsonProperty("allowCredentials") Optional<List<PublicKeyCredentialDescriptor>> allowCredentials
    ) {
        this.action = action;
        this.allowCredentials = allowCredentials;
    }
}
