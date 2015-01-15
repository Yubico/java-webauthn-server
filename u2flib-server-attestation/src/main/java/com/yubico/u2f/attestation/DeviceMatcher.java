/* Copyright 2015 Yubico */

package com.yubico.u2f.attestation;

import com.google.gson.JsonElement;

import java.security.cert.X509Certificate;

public interface DeviceMatcher {
    public boolean matches(X509Certificate attestationCertificate, JsonElement parameters);
}
