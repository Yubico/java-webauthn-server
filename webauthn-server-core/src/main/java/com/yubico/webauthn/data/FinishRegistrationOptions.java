package com.yubico.webauthn.data;

import java.util.Optional;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;

@Value
@Builder
public class FinishRegistrationOptions {

    @NonNull
    private final PublicKeyCredentialCreationOptions request;
    @NonNull
    private final PublicKeyCredential<AuthenticatorAttestationResponse> response;

    @NonNull
    @Builder.Default
    private final Optional<ByteArray> callerTokenBindingId = Optional.empty();

}
