/* Copyright 2015 Yubico */

package com.yubico.u2f.attestation.matchers;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.yubico.u2f.attestation.DeviceMatcher;
import org.bouncycastle.util.Strings;

import java.security.cert.X509Certificate;

public class ExtensionMatcher implements DeviceMatcher {
    private static final String EXTENSION_FIELD = "x509extension";
    private static final String EXTENSION_KEY = "key";
    private static final String EXTENSION_VALUE = "value";

    @Override
    public boolean matches(X509Certificate attestationCertificate, JsonObject selector) {
        JsonElement criteria = selector.get(EXTENSION_FIELD);
        if (criteria != null && criteria.isJsonObject()) {
            JsonElement matchKey = criteria.getAsJsonObject().get(EXTENSION_KEY);
            JsonElement matchValue = criteria.getAsJsonObject().get(EXTENSION_VALUE);
            if(matchKey != null) {
                byte[] extensionValue = attestationCertificate.getExtensionValue(matchKey.getAsString());
                if(matchValue == null || matchValue.getAsString().equals(Strings.fromByteArray(extensionValue))) {
                    return true;
                }
            }
        }
        return false;
    }
}
