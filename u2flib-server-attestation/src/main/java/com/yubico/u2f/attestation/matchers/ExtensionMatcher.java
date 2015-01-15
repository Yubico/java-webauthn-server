/* Copyright 2015 Yubico */

package com.yubico.u2f.attestation.matchers;

import com.google.gson.JsonElement;
import com.yubico.u2f.attestation.DeviceMatcher;
import org.bouncycastle.util.Strings;

import java.security.cert.X509Certificate;

public class ExtensionMatcher implements DeviceMatcher {
    public static final String EXTENSION_TYPE = "x509Extension";

    private static final String EXTENSION_KEY = "key";
    private static final String EXTENSION_VALUE = "value";

    @Override
    public boolean matches(X509Certificate attestationCertificate, JsonElement parameters) {
        String matchKey = parameters.getAsJsonObject().get(EXTENSION_KEY).getAsString();
        JsonElement matchValue = parameters.getAsJsonObject().get(EXTENSION_VALUE);
        byte[] extensionValue = attestationCertificate.getExtensionValue(matchKey);
        if (matchValue == null || matchValue.getAsString().equals(Strings.fromByteArray(extensionValue))) {
            return true;
        }
        return false;
    }
}
