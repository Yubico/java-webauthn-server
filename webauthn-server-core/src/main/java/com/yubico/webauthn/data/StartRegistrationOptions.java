package com.yubico.webauthn.data;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.Collection;
import java.util.Optional;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;

@Value
@Builder
public class StartRegistrationOptions {

    @NonNull
    private final UserIdentity user;

    @NonNull
    private final Optional<Collection<PublicKeyCredentialDescriptor>> excludeCredentials;

    @NonNull
    @Builder.Default
    private final Optional<JsonNode> extensions = Optional.empty();

    @Builder.Default
    private final boolean requireResidentKey = false;

}
