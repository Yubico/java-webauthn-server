package com.yubico.webauthn.data;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.Optional;
import org.junit.Test;

public class UserIdentityTest {

  @Test
  public void itHasTheseBuilderMethods() {
    UserIdentity.builder().name("").displayName("").id(new ByteArray(new byte[] {})).build();
  }

  @Test
  public void extraDataIsOptional() {
    final UserIdentity obj =
        UserIdentity.builder().name("").displayName("").id(new ByteArray(new byte[] {})).build();
    assertFalse(obj.getExtraData(Object.class).isPresent());
  }

  static class Foo {
    final String dummyValueForJson = "";
  }

  static class Bar {}

  @Test
  public void extraDataIsPreserved() {
    final Foo expectedAD = new Foo();
    final UserIdentity obj =
        UserIdentity.builder()
            .name("")
            .displayName("")
            .id(new ByteArray(new byte[] {}))
            .extraData(expectedAD)
            .build();

    final Optional<Foo> actualAD = obj.getExtraData(Foo.class);
    assertTrue(actualAD.isPresent() && actualAD.get() == expectedAD);
  }

  @Test
  public void extraDataIsTypeSafe() {
    final UserIdentity obj =
        UserIdentity.builder()
            .name("")
            .displayName("")
            .id(new ByteArray(new byte[] {}))
            .extraData(new Foo())
            .build();
    assertFalse(obj.getExtraData(Bar.class).isPresent());
  }

  @Test
  public void extraDataIsNotSerialized() throws JsonProcessingException {
    final UserIdentity one =
        UserIdentity.builder().name("").displayName("").id(new ByteArray(new byte[] {})).build();
    final UserIdentity two = one.toBuilder().extraData(new Foo()).build();

    final ObjectMapper mapper = new ObjectMapper();
    final String expected = mapper.writeValueAsString(one);
    final String actual = mapper.writeValueAsString(two);
    assertEquals(expected, actual);
    assertEquals(one, mapper.readValue(actual, UserIdentity.class));
  }
}
