package com.yubico.u2f.attestation;

import com.google.gson.JsonObject;

import java.security.cert.X509Certificate;

/**
 * Created by dain on 12/5/14.
 */
public interface DeviceMatcher {
    public boolean matches(X509Certificate attestationCertificate, JsonObject selector);
}
