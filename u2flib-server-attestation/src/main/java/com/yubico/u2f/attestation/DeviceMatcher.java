/* Copyright 2015 Yubico */

package com.yubico.u2f.attestation;

import com.fasterxml.jackson.databind.JsonNode;

import java.security.cert.X509Certificate;

public interface DeviceMatcher {
    public boolean matches(X509Certificate attestationCertificate, JsonNode parameters);
}
