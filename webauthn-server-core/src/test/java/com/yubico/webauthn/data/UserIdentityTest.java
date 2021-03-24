package com.yubico.webauthn.data;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Optional;
import org.junit.Test;

public class UserIdentityTest {

  @Test
  public void itHasTheseBuilderMethods() throws MalformedURLException {
    UserIdentity.builder()
        .name("")
        .displayName("")
        .id(new ByteArray(new byte[] {}))
        .icon(new URL("https://example.com"))
        .icon(Optional.of(new URL("https://example.com")));
  }
}
