package com.yubico.webauthn.data;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.Collections;
import java.util.Optional;
import java.util.Set;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;

@Value
@Builder
public class StartRegistrationOptions {

    @NonNull
    private final UserIdentity user;

    @NonNull
    private final Optional<Set<PublicKeyCredentialDescriptor>> excludeCredentials;

    @NonNull
    @Builder.Default
    private final Optional<JsonNode> extensions = Optional.empty();

    @Builder.Default
    private final boolean requireResidentKey = false;

    public StartRegistrationOptions(
        UserIdentity user,
        Optional<Set<PublicKeyCredentialDescriptor>> excludeCredentials,
        Optional<JsonNode> extensions,
        boolean requireResidentKey
    ) {
        this.user = user;
        this.excludeCredentials = excludeCredentials.map(Collections::unmodifiableSet);
        this.extensions = extensions;
        this.requireResidentKey = requireResidentKey;
    }

}
