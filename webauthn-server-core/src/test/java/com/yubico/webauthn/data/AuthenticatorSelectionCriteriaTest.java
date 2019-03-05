package com.yubico.webauthn.data;

import java.util.Optional;
import org.junit.Test;

public class AuthenticatorSelectionCriteriaTest {

    @Test
    public void itHasTheseBuilderMethods() {
        AuthenticatorSelectionCriteria.builder()
            .authenticatorAttachment(AuthenticatorAttachment.CROSS_PLATFORM)
            .authenticatorAttachment(Optional.of(AuthenticatorAttachment.CROSS_PLATFORM))
            .requireResidentKey(false)
            .userVerification(UserVerificationRequirement.PREFERRED)
            .build();
    }

}
