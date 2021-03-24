package com.yubico.webauthn;

import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.exception.HexException;
import java.util.Optional;
import org.junit.Test;

public class FinishAssertionOptionsTest {

  @Test(expected = NullPointerException.class)
  public void itHasANonOptionalCallerTokenBindingIdMethod() throws HexException {
    FinishAssertionOptions.builder()
        .request(null)
        .response(null)
        .callerTokenBindingId(ByteArray.fromHex("aa"));
  }

  @Test(expected = NullPointerException.class)
  public void itHasAnOptionalCallerTokenBindingIdMethod() throws HexException {
    FinishAssertionOptions.builder()
        .request(null)
        .response(null)
        .callerTokenBindingId(Optional.of(ByteArray.fromHex("aa")));
  }
}
