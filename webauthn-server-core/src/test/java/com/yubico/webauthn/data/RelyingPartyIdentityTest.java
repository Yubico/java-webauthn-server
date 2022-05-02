package com.yubico.webauthn.data;

import org.junit.Test;

public class RelyingPartyIdentityTest {

  @Test
  public void itHasTheseBuilderMethods() {
    RelyingPartyIdentity.builder().id("").name("").build();
  }
}
