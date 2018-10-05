package com.yubico.webauthn;

import com.yubico.webauthn.data.AuthenticatorSelectionCriteria;
import com.yubico.webauthn.data.RegistrationExtensionInputs;
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
    private final Optional<AuthenticatorSelectionCriteria> authenticatorSelection = Optional.empty();

    @NonNull
    @Builder.Default
    private final RegistrationExtensionInputs extensions = RegistrationExtensionInputs.builder().build();

}
