package com.yubico.webauthn.data;

import com.yubico.webauthn.extension.appid.AppId;
import com.yubico.webauthn.extension.appid.InvalidAppIdException;
import java.util.Optional;
import org.junit.Test;

public class AssertionExtensionInputsTest {

  @Test
  public void itHasTheseBuilderMethods() throws InvalidAppIdException {
    AssertionExtensionInputs.builder()
        .appid(new AppId("https://example.com"))
        .appid(Optional.of(new AppId("https://example.com")))
        .build();
  }
}
