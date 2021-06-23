package com.yubico.webauthn.data;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import com.yubico.webauthn.data.exception.HexException;
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
import uk.org.lidalia.slf4jext.Level;
import uk.org.lidalia.slf4jtest.TestLogger;
import uk.org.lidalia.slf4jtest.TestLoggerFactory;

public class PublicKeyCredentialCreationOptionsTest {

  private static final TestLogger testLog =
      TestLoggerFactory.getTestLogger(PublicKeyCredentialCreationOptions.class);
  private List<Provider> providersBefore;

  @Before
  public void setUp() {
    providersBefore = Stream.of(Security.getProviders()).collect(Collectors.toList());
    testLog.clearAll();
  }

  @After
  public void tearDown() {
    for (Provider prov : Security.getProviders()) {
      Security.removeProvider(prov.getName());
    }
    providersBefore.forEach(Security::addProvider);
    testLog.clearAll();
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

  @Test
  public void filtersAlgorithmsToThoseAvailable() throws HexException {
    for (Provider prov : Security.getProviders()) {
      if (prov.getName().contains("EC")) {
        Security.removeProvider(prov.getName());
      }
    }

    PublicKeyCredentialCreationOptions pkcco =
        PublicKeyCredentialCreationOptions.builder()
            .rp(RelyingPartyIdentity.builder().id("localhost").name("Test").build())
            .user(
                UserIdentity.builder()
                    .name("foo")
                    .displayName("Foo User")
                    .id(ByteArray.fromHex("00010203"))
                    .build())
            .challenge(ByteArray.fromHex("04050607"))
            .pubKeyCredParams(
                Stream.of(PublicKeyCredentialParameters.ES256, PublicKeyCredentialParameters.RS256)
                    .collect(Collectors.toList()))
            .build();

    assertEquals(
        Collections.singletonList(PublicKeyCredentialParameters.RS256),
        pkcco.getPubKeyCredParams());
  }

  @Test
  public void defaultProvidersDontFilterEs256OrRs256() throws HexException {
    PublicKeyCredentialCreationOptions pkcco =
        PublicKeyCredentialCreationOptions.builder()
            .rp(RelyingPartyIdentity.builder().id("localhost").name("Test").build())
            .user(
                UserIdentity.builder()
                    .name("foo")
                    .displayName("Foo User")
                    .id(ByteArray.fromHex("00010203"))
                    .build())
            .challenge(ByteArray.fromHex("04050607"))
            .pubKeyCredParams(
                Stream.of(PublicKeyCredentialParameters.ES256, PublicKeyCredentialParameters.RS256)
                    .collect(Collectors.toList()))
            .build();

    assertEquals(
        Stream.of(PublicKeyCredentialParameters.ES256, PublicKeyCredentialParameters.RS256)
            .collect(Collectors.toList()),
        pkcco.getPubKeyCredParams());
  }

  @Test
  public void logsWarningIfAlgorithmNotAvailable() throws HexException {
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

    assertTrue(
        "Expected warning log containing \"ES256\" and (case-insensitive) \"unsupported algorithm\".",
        testLog.getLoggingEvents().stream()
            .anyMatch(
                event ->
                    event.getLevel().compareTo(Level.WARN) >= 0
                        && event.getArguments().stream()
                            .anyMatch(arg -> "ES256".equals(arg.toString()))
                        && event.getMessage().toLowerCase().contains("unsupported algorithm")));
  }

  @Test
  public void doesNotLogWarningIfAllAlgorithmsAvailable() throws HexException {
    PublicKeyCredentialCreationOptions.builder()
        .rp(RelyingPartyIdentity.builder().id("localhost").name("Test").build())
        .user(
            UserIdentity.builder()
                .name("foo")
                .displayName("Foo User")
                .id(ByteArray.fromHex("00010203"))
                .build())
        .challenge(ByteArray.fromHex("04050607"))
        .pubKeyCredParams(
            Stream.of(PublicKeyCredentialParameters.ES256, PublicKeyCredentialParameters.RS256)
                .collect(Collectors.toList()))
        .build();

    assertEquals(0, testLog.getAllLoggingEvents().size());
  }
}
