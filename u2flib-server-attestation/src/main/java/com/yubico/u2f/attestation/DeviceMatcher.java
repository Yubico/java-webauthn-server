/* Copyright 2015 Yubico */

package com.yubico.u2f.attestation;

import com.google.gson.JsonObject;

import java.security.cert.X509Certificate;

public interface DeviceMatcher {
    public boolean matches(X509Certificate attestationCertificate, JsonObject selector);
}
