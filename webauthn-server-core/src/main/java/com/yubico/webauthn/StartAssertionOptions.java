package com.yubico.webauthn;

import com.fasterxml.jackson.databind.node.ObjectNode;
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
    private final Optional<ObjectNode> extensions = Optional.empty();


}
