package com.yubico.webauthn.data;

import java.util.Optional;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;


@Value
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
public class AssertionRequest {

    @NonNull
    private final ByteArray requestId;

    @NonNull
    private final PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions;

    @NonNull
    @Builder.Default
    private final Optional<String> username = Optional.empty();

}
