package com.yubico.webauthn.data;

import com.yubico.webauthn.data.exception.HexException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class PublicKeyCredentialCreationOptionsTest {

  private List<Provider> providersBefore;

  @Before
  public void setUp() {
    providersBefore = Stream.of(Security.getProviders()).collect(Collectors.toList());
  }

  @After
  public void tearDown() {
    for (Provider prov : Security.getProviders()) {
      Security.removeProvider(prov.getName());
    }
    providersBefore.forEach(Security::addProvider);
  }

  @Test(expected = NullPointerException.class)
  public void itHasTheseBuilderMethods() {
    PublicKeyCredentialCreationOptions.builder()
        .rp(null)
        .user(null)
        .challenge(null)
        .pubKeyCredParams(null)
        .attestation(null)
        .authenticatorSelection(AuthenticatorSelectionCriteria.builder().build())
        .authenticatorSelection(Optional.of(AuthenticatorSelectionCriteria.builder().build()))
        .excludeCredentials(Collections.emptySet())
        .excludeCredentials(Optional.of(Collections.emptySet()))
        .extensions(RegistrationExtensionInputs.builder().build())
        .timeout(0)
        .timeout(Optional.of(0L));
  }

  @Test(expected = NoSuchAlgorithmException.class)
  public void throwsIfAlgorithmNotAvailable() throws HexException {
    for (Provider prov : Security.getProviders()) {
      if (prov.getName().contains("EC")) {
        Security.removeProvider(prov.getName());
      }
    }
    PublicKeyCredentialCreationOptions.builder()
        .rp(RelyingPartyIdentity.builder().id("localhost").name("Test").build())
        .user(
            UserIdentity.builder()
                .name("foo")
                .displayName("Foo User")
                .id(ByteArray.fromHex("00010203"))
                .build())
        .challenge(ByteArray.fromHex("04050607"))
        .pubKeyCredParams(Collections.singletonList(PublicKeyCredentialParameters.ES256))
        .build();
  }
}
