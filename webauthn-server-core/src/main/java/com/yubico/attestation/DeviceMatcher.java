/* Copyright 2015 Yubico */

package com.yubico.attestation;

import com.fasterxml.jackson.databind.JsonNode;
import java.security.cert.X509Certificate;

public interface DeviceMatcher {
    boolean matches(X509Certificate attestationCertificate, JsonNode parameters);
}
