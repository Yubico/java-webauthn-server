package com.yubico.webauthn;

import com.yubico.webauthn.data.AuthenticatorAttestationResponse;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
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
