package com.yubico.webauthn;

import com.yubico.webauthn.data.AssertionExtensionInputs;
import com.yubico.webauthn.data.UserVerificationRequirement;
import java.util.Optional;
import org.junit.Test;

public class StartAssertionOptionsTest {

    @Test
    public void itHasTheseBuilderMethods() {
        StartAssertionOptions.builder()
            .username("")
            .username(Optional.of(""))
            .extensions(AssertionExtensionInputs.builder().build())
            .userVerification(UserVerificationRequirement.REQUIRED)
            .userVerification(Optional.of(UserVerificationRequirement.REQUIRED))
            .timeout(0)
            .timeout(Optional.of(0l))
            .build();
    }

}
