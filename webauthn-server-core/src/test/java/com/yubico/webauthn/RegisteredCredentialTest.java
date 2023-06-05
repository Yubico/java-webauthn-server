package com.yubico.webauthn;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.yubico.webauthn.data.ByteArray;
import java.util.Optional;
import org.junit.Test;

public class RegisteredCredentialTest {

  private static ByteArray blank() {
    return new ByteArray(new byte[] {});
  }

  @Test
  public void itHasTheseBuilderMethods() {
    RegisteredCredential.builder()
        .credentialId(blank())
        .userHandle(blank())
        .publicKeyCose(blank())
        .build();
  }

  @Test
  public void extraDataIsOptional() {
    final RegisteredCredential obj =
        RegisteredCredential.builder()
            .credentialId(blank())
            .userHandle(blank())
            .publicKeyCose(blank())
            .build();
    assertFalse(obj.getExtraData(Object.class).isPresent());
  }

  static class Foo {
    final String dummyValueForJson = "";
  }

  static class Bar {}

  @Test
  public void extraDataIsPreserved() {
    final Foo expectedAD = new Foo();
    final RegisteredCredential obj =
        RegisteredCredential.builder()
            .credentialId(blank())
            .userHandle(blank())
            .publicKeyCose(blank())
            .extraData(expectedAD)
            .build();

    final Optional<Foo> actualAD = obj.getExtraData(Foo.class);
    assertTrue(actualAD.isPresent() && actualAD.get() == expectedAD);
  }

  @Test
  public void extraDataIsTypeSafe() {
    final RegisteredCredential obj =
        RegisteredCredential.builder()
            .credentialId(blank())
            .userHandle(blank())
            .publicKeyCose(blank())
            .extraData(new Foo())
            .build();
    assertFalse(obj.getExtraData(Bar.class).isPresent());
  }

  @Test
  public void extraDataIsNotSerialized() throws JsonProcessingException {
    final RegisteredCredential one =
        RegisteredCredential.builder()
            .credentialId(blank())
            .userHandle(blank())
            .publicKeyCose(blank())
            .build();
    final RegisteredCredential two = one.toBuilder().extraData(new Foo()).build();

    final ObjectMapper mapper = new ObjectMapper();
    final String expected = mapper.writeValueAsString(one);
    final String actual = mapper.writeValueAsString(two);
    assertEquals(expected, actual);
    assertEquals(one, mapper.readValue(actual, RegisteredCredential.class));
  }
}
