package com.yubico.webauthn;

import com.yubico.webauthn.data.AuthenticatorSelectionCriteria;
import com.yubico.webauthn.data.RegistrationExtensionInputs;
import java.util.Optional;
import org.junit.Test;

public class StartRegistrationOptionsTest {

  @Test(expected = NullPointerException.class)
  public void itHasTheseBuilderMethods() {
    StartRegistrationOptions.builder()
        .user(null)
        .authenticatorSelection(AuthenticatorSelectionCriteria.builder().build())
        .authenticatorSelection(Optional.of(AuthenticatorSelectionCriteria.builder().build()))
        .extensions(RegistrationExtensionInputs.builder().build())
        .build();
  }
}
