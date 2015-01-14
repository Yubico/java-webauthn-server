/* Copyright 2015 Yubico */

package com.yubico.u2f.attestation.matchers;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.yubico.u2f.attestation.DeviceMatcher;

import java.security.cert.X509Certificate;

public class OidMatcher implements DeviceMatcher {
    private static final String EXTENSION_OID_EXISTS = "oid";

    @Override
    public boolean matches(X509Certificate attestationCertificate, JsonObject selector) {
        JsonElement oid = selector.get(EXTENSION_OID_EXISTS);
        if (oid != null && oid.isJsonPrimitive() && oid.getAsJsonPrimitive().isString()) {
            return attestationCertificate.getExtensionValue(oid.getAsString()) != null;
        }
        return false;
    }
}
