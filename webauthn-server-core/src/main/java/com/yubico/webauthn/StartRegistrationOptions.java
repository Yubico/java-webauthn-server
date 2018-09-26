package com.yubico.webauthn;

import com.fasterxml.jackson.databind.node.ObjectNode;
import com.yubico.webauthn.data.UserIdentity;
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
    @Builder.Default
    private final Optional<ObjectNode> extensions = Optional.empty();

    @Builder.Default
    private final boolean requireResidentKey = false;

}
