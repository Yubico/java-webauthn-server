package com.yubico.webauthn;

import com.yubico.internal.util.CertificateParser;
import com.yubico.webauthn.attestation.Attestation;
import com.yubico.webauthn.attestation.MetadataService;
import com.yubico.webauthn.data.AttestationObject;
import java.io.IOException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;


@Slf4j
@AllArgsConstructor
class KnownX509TrustAnchorsTrustResolver implements AttestationTrustResolver {

    private final MetadataService metadataService;

    @Override
    public Attestation resolveTrustAnchor(AttestationObject attestationObject) throws CertificateEncodingException {
        return metadataService.getAttestation(
            StreamSupport.stream(
                attestationObject
                    .getAttestationStatement()
                    .get("x5c")
                    .spliterator(),
                true
            )
                .map(node -> {
                    try {
                        return CertificateParser.parseDer(node.binaryValue());
                    } catch (CertificateException | IOException e) {
                        log.error("Failed to parse attestation certificate from attestation object: {}", attestationObject, e);
                        throw new RuntimeException(e);
                    }
                })
                .collect(Collectors.toList())
        );
    }

}

