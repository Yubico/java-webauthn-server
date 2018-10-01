package com.yubico.webauthn;

import com.yubico.webauthn.data.AssertionExtensionInputs;
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
    private final AssertionExtensionInputs extensions = AssertionExtensionInputs.builder().build();


}
