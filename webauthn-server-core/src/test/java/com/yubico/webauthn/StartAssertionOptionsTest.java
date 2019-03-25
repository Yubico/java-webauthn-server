package com.yubico.webauthn;

import com.yubico.webauthn.data.AuthenticatorSelectionCriteria;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.RegistrationExtensionInputs;
import com.yubico.webauthn.data.UserIdentity;
import java.util.Optional;
import org.junit.Test;

public class StartAssertionOptionsTest {

    @Test
    public void itHasTheseBuilderMethods() {
        StartRegistrationOptions.builder()
            .user(UserIdentity.builder().name("").displayName("").id(new ByteArray(new byte[]{})).build())
            .authenticatorSelection(AuthenticatorSelectionCriteria.builder().build())
            .authenticatorSelection(Optional.of(AuthenticatorSelectionCriteria.builder().build()))
            .extensions(RegistrationExtensionInputs.builder().build())
            .build();
    }

}
