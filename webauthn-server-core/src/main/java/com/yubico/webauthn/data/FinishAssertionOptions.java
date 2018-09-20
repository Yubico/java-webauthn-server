package com.yubico.webauthn.data;

import java.util.Optional;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;

@Value
@Builder
public class FinishAssertionOptions {

    @NonNull
    private final AssertionRequest request;
    @NonNull
    private final PublicKeyCredential<AuthenticatorAssertionResponse> response;

    @NonNull
    @Builder.Default
    private final Optional<ByteArray> callerTokenBindingId = Optional.empty();

}
