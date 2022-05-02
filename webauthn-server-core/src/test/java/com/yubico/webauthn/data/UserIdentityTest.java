package com.yubico.webauthn.data;

import org.junit.Test;

public class UserIdentityTest {

  @Test
  public void itHasTheseBuilderMethods() {
    UserIdentity.builder().name("").displayName("").id(new ByteArray(new byte[] {})).build();
  }
}
