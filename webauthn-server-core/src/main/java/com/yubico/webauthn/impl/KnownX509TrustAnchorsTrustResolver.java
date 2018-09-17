package com.yubico.webauthn.impl;

import com.yubico.attestation.Attestation;
import com.yubico.attestation.MetadataService;
import com.yubico.util.CertificateParser;
import com.yubico.webauthn.AttestationTrustResolver;
import com.yubico.webauthn.data.AttestationObject;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;


@Slf4j
@AllArgsConstructor
public class KnownX509TrustAnchorsTrustResolver implements AttestationTrustResolver {

    private final MetadataService metadataService;

    @Override
    public Optional<Attestation> resolveTrustAnchor(AttestationObject attestationObject) {
        return Optional.ofNullable(
            metadataService.getAttestation(
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
            )
        );
    }

}

