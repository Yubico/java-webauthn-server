package com.yubico.webauthn.data;

import java.util.Optional;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Value;


@Value
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
public class AssertionRequest {

    private final ByteArray requestId;
    private final PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions;

    @Builder.Default
    private final Optional<String> username = Optional.empty();

}
