package com.yubico.webauthn.data;

import java.util.Optional;
import lombok.Builder;
import lombok.Value;


@Value
@Builder
public class AssertionRequest {

    private final ByteArray requestId;
    private final PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions;

    @Builder.Default
    private final Optional<String> username = Optional.empty();

}
