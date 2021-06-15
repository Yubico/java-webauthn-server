package com.yubico.webauthn;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import com.yubico.webauthn.attestation.Attestation;
import com.yubico.webauthn.attestation.MetadataService;
import com.yubico.webauthn.data.AttestationConveyancePreference;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.PublicKeyCredentialParameters;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import com.yubico.webauthn.extension.appid.AppId;
import com.yubico.webauthn.extension.appid.InvalidAppIdException;
import java.security.NoSuchAlgorithmException;
import java.security.Provider;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class RelyingPartyTest {

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
  public void itHasTheseBuilderMethods() throws InvalidAppIdException {

    final MetadataService metadataService =
        new MetadataService() {
          @Override
          public Attestation getAttestation(List<X509Certificate> attestationCertificateChain)
              throws CertificateEncodingException {
            return null;
          }
        };

    RelyingParty.builder()
        .identity(null)
        .credentialRepository(null)
        .origins(Collections.emptySet())
        .appId(new AppId("https://example.com"))
        .appId(Optional.of(new AppId("https://example.com")))
        .attestationConveyancePreference(AttestationConveyancePreference.DIRECT)
        .attestationConveyancePreference(Optional.of(AttestationConveyancePreference.DIRECT))
        .metadataService(metadataService)
        .metadataService(Optional.of(metadataService))
        .preferredPubkeyParams(Collections.emptyList())
        .allowUntrustedAttestation(true)
        .validateSignatureCounter(true);
  }

  @Test
  public void originsIsImmutable() {
    Set<String> origins = new HashSet<>();

    RelyingParty rp =
        RelyingParty.builder()
            .identity(RelyingPartyIdentity.builder().id("localhost").name("Test").build())
            .credentialRepository(unimplementedCredentialRepository())
            .origins(origins)
            .build();

    assertEquals(0, rp.getOrigins().size());

    origins.add("test");
    assertEquals(0, rp.getOrigins().size());

    try {
      rp.getOrigins().add("test");
      fail("Expected UnsupportedOperationException to be thrown");
    } catch (UnsupportedOperationException e) {
      assertEquals(0, rp.getOrigins().size());
    }
  }

  @Test(expected = NoSuchAlgorithmException.class)
  public void defaultSettingsThrowIfSomeAlgorithmNotAvailable() {
    for (Provider prov : Security.getProviders()) {
      if (prov.getName().contains("EC")) {
        Security.removeProvider(prov.getName());
      }
    }
    RelyingParty.builder()
        .identity(RelyingPartyIdentity.builder().id("localhost").name("Test").build())
        .credentialRepository(unimplementedCredentialRepository())
        .build();
  }

  @Test(expected = NoSuchAlgorithmException.class)
  public void throwsIfAlgorithmNotAvailable() {
    for (Provider prov : Security.getProviders()) {
      if (prov.getName().contains("EC")) {
        Security.removeProvider(prov.getName());
      }
    }
    RelyingParty.builder()
        .identity(RelyingPartyIdentity.builder().id("localhost").name("Test").build())
        .credentialRepository(unimplementedCredentialRepository())
        .preferredPubkeyParams(Collections.singletonList(PublicKeyCredentialParameters.ES256))
        .build();
  }

  private static CredentialRepository unimplementedCredentialRepository() {
    return new CredentialRepository() {
      @Override
      public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
        return null;
      }

      @Override
      public Optional<ByteArray> getUserHandleForUsername(String username) {
        return Optional.empty();
      }

      @Override
      public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
        return Optional.empty();
      }

      @Override
      public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
        return Optional.empty();
      }

      @Override
      public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {
        return null;
      }
    };
  }
}
