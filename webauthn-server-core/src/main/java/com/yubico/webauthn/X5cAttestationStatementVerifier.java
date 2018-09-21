package com.yubico.webauthn;

import com.fasterxml.jackson.databind.JsonNode;
import com.yubico.internal.util.CertificateParser;
import com.yubico.webauthn.data.AttestationObject;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;


interface X5cAttestationStatementVerifier {

    default Optional<X509Certificate> getX5cAttestationCertificate(AttestationObject attestationObject) throws CertificateException {
        return getAttestationTrustPath(attestationObject).flatMap(certs -> certs.stream().findFirst());
    }

    default Optional<List<X509Certificate>> getAttestationTrustPath(AttestationObject attestationObject) throws CertificateException {
        JsonNode x5cNode = attestationObject.getAttestationStatement().get("x5c");

        if (x5cNode != null && x5cNode.isArray()) {
            List<X509Certificate> certs = new ArrayList<>(x5cNode.size());

            for (JsonNode binary : x5cNode) {
                if (binary.isBinary()) {
                    try {
                        certs.add(CertificateParser.parseDer(binary.binaryValue()));
                    } catch (IOException e) {
                        throw new RuntimeException("binary.isBinary() was true but binary.binaryValue() failed", e);
                    }
                } else {
                    throw new IllegalArgumentException(String.format(
                        "Each element of \"x5c\" property of attestation statement must be a binary value, was: %s",
                        binary.getNodeType()
                    ));
                }
            }

            return Optional.of(certs);
        } else {
            return Optional.empty();
        }
    }

}
