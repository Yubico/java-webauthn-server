package com.yubico.webauthn.data;

import java.util.Collections;
import java.util.Optional;
import org.junit.Test;

public class PublicKeyCredentialCreationOptionsTest {

  @Test(expected = NullPointerException.class)
  public void itHasTheseBuilderMethods() {
    PublicKeyCredentialCreationOptions.builder()
        .rp(null)
        .user(null)
        .challenge(null)
        .pubKeyCredParams(null)
        .attestation(null)
        .authenticatorSelection(AuthenticatorSelectionCriteria.builder().build())
        .authenticatorSelection(Optional.of(AuthenticatorSelectionCriteria.builder().build()))
        .excludeCredentials(Collections.emptySet())
        .excludeCredentials(Optional.of(Collections.emptySet()))
        .extensions(RegistrationExtensionInputs.builder().build())
        .timeout(0)
        .timeout(Optional.of(0L));
  }
}
