package com.yubico.u2f.attestation.matchers;

import com.fasterxml.jackson.databind.JsonNode;
import com.google.common.hash.Hashing;
import com.yubico.u2f.attestation.DeviceMatcher;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

public class FingerprintMatcher implements DeviceMatcher {
    public static final String SELECTOR_TYPE = "fingerprint";

    private static final String FINGERPRINTS_KEY = "fingerprints";

    @Override
    public boolean matches(X509Certificate attestationCertificate, JsonNode parameters) {
        JsonNode fingerprints = parameters.get(FINGERPRINTS_KEY);
        if(fingerprints.isArray()) {
            try {
                String fingerprint = Hashing.sha1().hashBytes(attestationCertificate.getEncoded()).toString().toLowerCase();
                for(JsonNode candidate : fingerprints) {
                    if(fingerprint.equals(candidate.asText().toLowerCase())) {
                        return true;
                    }
                }
            } catch (CertificateEncodingException e) {
                //Fall through to return false.
            }
        }
        return false;
    }
}
