package com.yubico.webauthn.data;

import java.util.Collections;
import java.util.Optional;
import org.junit.Test;

public class PublicKeyCredentialRequestOptionsTest {

  @Test(expected = NullPointerException.class)
  public void itHasTheseBuilderMethods() {
    PublicKeyCredentialRequestOptions.builder()
        .challenge(null)
        .timeout(0)
        .timeout(Optional.of(0L))
        .rpId("")
        .rpId(Optional.of(""))
        .allowCredentials(Collections.emptyList())
        .allowCredentials(Optional.of(Collections.emptyList()))
        .userVerification(UserVerificationRequirement.PREFERRED)
        .extensions(AssertionExtensionInputs.builder().build());
  }
}
