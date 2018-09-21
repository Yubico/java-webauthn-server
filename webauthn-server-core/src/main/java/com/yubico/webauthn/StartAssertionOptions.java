package com.yubico.webauthn;

import com.fasterxml.jackson.databind.JsonNode;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import java.util.List;
import java.util.Optional;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;

@Value
@Builder
public class StartAssertionOptions {

    @NonNull
    @Builder.Default
    private final Optional<String> username = Optional.empty();

    @NonNull
    @Builder.Default
    private final Optional<List<PublicKeyCredentialDescriptor>> allowCredentials = Optional.empty();

    @NonNull
    @Builder.Default
    private final Optional<JsonNode> extensions = Optional.empty();

}
