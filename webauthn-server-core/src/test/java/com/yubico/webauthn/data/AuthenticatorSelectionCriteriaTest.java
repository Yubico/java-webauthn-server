package com.yubico.webauthn.data;

import static org.junit.Assert.assertEquals;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.yubico.internal.util.JacksonCodecs;
import java.util.Optional;
import org.junit.Test;

public class AuthenticatorSelectionCriteriaTest {

  @Test
  public void itHasTheseBuilderMethods() {
    AuthenticatorSelectionCriteria.builder()
        .authenticatorAttachment(AuthenticatorAttachment.CROSS_PLATFORM)
        .authenticatorAttachment(Optional.of(AuthenticatorAttachment.CROSS_PLATFORM))
        .requireResidentKey(false)
        .residentKey(ResidentKeyRequirement.REQUIRED)
        .userVerification(UserVerificationRequirement.PREFERRED)
        .build();
  }

  @Test
  public void newResidentKeyOverridesOld() throws JsonProcessingException {
    ObjectMapper json = JacksonCodecs.json();
    AuthenticatorSelectionCriteria decoded =
        json.readValue(
            "{\"requireResidentKey\": false, \"residentKey\": \"required\"}",
            AuthenticatorSelectionCriteria.class);
    assertEquals(decoded.getResidentKey(), ResidentKeyRequirement.REQUIRED);
    assertEquals(decoded.isRequireResidentKey(), true);
  }

  @Test
  public void newResidentKeyFallsBackToOld() throws JsonProcessingException {
    ObjectMapper json = JacksonCodecs.json();
    AuthenticatorSelectionCriteria decoded =
        json.readValue("{\"requireResidentKey\": true}", AuthenticatorSelectionCriteria.class);
    assertEquals(decoded.getResidentKey(), ResidentKeyRequirement.REQUIRED);
    assertEquals(decoded.isRequireResidentKey(), true);
  }
}
