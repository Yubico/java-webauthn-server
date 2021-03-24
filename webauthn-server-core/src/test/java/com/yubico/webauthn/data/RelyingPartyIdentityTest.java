package com.yubico.webauthn.data;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.Optional;
import org.junit.Test;

public class RelyingPartyIdentityTest {

  @Test
  public void itHasTheseBuilderMethods() throws MalformedURLException {
    RelyingPartyIdentity.builder()
        .id("")
        .name("")
        .icon(new URL("https://example.com"))
        .icon(Optional.of(new URL("https://example.com")));
  }
}
