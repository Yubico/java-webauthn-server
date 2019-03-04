package com.yubico.webauthn;

import com.yubico.webauthn.attestation.Attestation;
import com.yubico.webauthn.attestation.MetadataService;
import com.yubico.webauthn.data.AttestationConveyancePreference;
import com.yubico.webauthn.extension.appid.AppId;
import com.yubico.webauthn.extension.appid.InvalidAppIdException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import org.junit.Test;

public class RelyingPartyTest {

    @Test(expected = NullPointerException.class)
    public void itHasTheseBuilderMethods() throws InvalidAppIdException {

        final MetadataService metadataService = new MetadataService() {
            @Override public Attestation getAttestation(List<X509Certificate> attestationCertificateChain) throws CertificateEncodingException { return null; }
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
            .validateSignatureCounter(true)
        ;
    }

}
