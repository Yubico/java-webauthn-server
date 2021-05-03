package com.yubico.webauthn;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import com.yubico.webauthn.attestation.Attestation;
import com.yubico.webauthn.attestation.MetadataService;
import com.yubico.webauthn.data.AttestationConveyancePreference;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import com.yubico.webauthn.extension.appid.AppId;
import com.yubico.webauthn.extension.appid.InvalidAppIdException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import org.junit.Test;

public class RelyingPartyTest {

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
        .allowUnrequestedExtensions(true)
        .allowUntrustedAttestation(true)
        .validateSignatureCounter(true);
  }

  @Test
  public void originsIsImmutable() {
    Set<String> origins = new HashSet<>();

    RelyingParty rp =
        RelyingParty.builder()
            .identity(RelyingPartyIdentity.builder().id("localhost").name("Test").build())
            .credentialRepository(
                new CredentialRepository() {
                  @Override
                  public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(
                      String username) {
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
                  public Optional<RegisteredCredential> lookup(
                      ByteArray credentialId, ByteArray userHandle) {
                    return Optional.empty();
                  }

                  @Override
                  public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {
                    return null;
                  }
                })
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
}
