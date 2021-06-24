package com.yubico.webauthn;

import static org.junit.Assert.assertTrue;

import COSE.CoseException;
import com.yubico.webauthn.data.AttestationObject;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.Mockito;

/**
 * Test that the BouncyCastle provider is not loaded by default.
 *
 * <p>Motivation: https://github.com/Yubico/java-webauthn-server/issues/97
 */
public class BouncyCastleProviderPresenceTest {

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

  private static boolean isNamedBouncyCastle(Provider prov) {
    return prov.getName().equals("BC") || prov.getClass().getCanonicalName().contains("bouncy");
  }

  @Test
  public void bouncyCastleProviderIsInClasspath() {
    new BouncyCastleProvider();
  }

  @Test
  public void bouncyCastleProviderIsNotLoadedByDefault() {
    assertTrue(
        Arrays.stream(Security.getProviders())
            .noneMatch(BouncyCastleProviderPresenceTest::isNamedBouncyCastle));
  }

  @Test
  public void bouncyCastleProviderIsNotLoadedAfterInstantiatingRelyingParty() {
    RelyingParty.builder()
        .identity(RelyingPartyIdentity.builder().id("foo").name("foo").build())
        .credentialRepository(Mockito.mock(CredentialRepository.class))
        .build();

    assertTrue(
        Arrays.stream(Security.getProviders())
            .noneMatch(BouncyCastleProviderPresenceTest::isNamedBouncyCastle));
  }

  @Test
  public void bouncyCastleProviderIsNotLoadedAfterAttemptingToLoadEddsaKey()
      throws IOException, CoseException, InvalidKeySpecException {
    try {
      WebAuthnCodecs.importCosePublicKey(
          new AttestationObject(
                  RegistrationTestData.Packed$.MODULE$.BasicAttestationEdDsa().attestationObject())
              .getAuthenticatorData()
              .getAttestedCredentialData()
              .get()
              .getCredentialPublicKey());
    } catch (NoSuchAlgorithmException e) {
      // OK
    }

    assertTrue(
        Arrays.stream(Security.getProviders())
            .noneMatch(BouncyCastleProviderPresenceTest::isNamedBouncyCastle));
  }

  @Test(expected = NoSuchAlgorithmException.class)
  public void doesNotFallBackToBouncyCastleAutomatically()
      throws IOException, CoseException, InvalidKeySpecException, NoSuchAlgorithmException {
    for (Provider prov : Security.getProviders()) {
      Security.removeProvider(prov.getName());
    }

    WebAuthnCodecs.importCosePublicKey(
        new AttestationObject(
                RegistrationTestData.Packed$.MODULE$.BasicAttestationEdDsa().attestationObject())
            .getAuthenticatorData()
            .getAttestedCredentialData()
            .get()
            .getCredentialPublicKey());
  }
}
