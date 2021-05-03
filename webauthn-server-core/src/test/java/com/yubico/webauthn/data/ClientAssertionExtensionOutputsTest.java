package com.yubico.webauthn.data;

import java.util.Optional;
import org.junit.Test;

public class ClientAssertionExtensionOutputsTest {

  @Test
  public void itHasTheseBuilderMethods() {
    ClientAssertionExtensionOutputs.builder().appid(false).appid(Optional.of(false)).build();
  }
}
