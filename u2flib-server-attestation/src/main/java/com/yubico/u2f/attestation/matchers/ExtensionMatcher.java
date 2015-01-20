/* Copyright 2015 Yubico */

package com.yubico.u2f.attestation.matchers;

import com.fasterxml.jackson.databind.JsonNode;
import com.yubico.u2f.attestation.DeviceMatcher;
import org.bouncycastle.util.Strings;

import java.security.cert.X509Certificate;

public class ExtensionMatcher implements DeviceMatcher {
    public static final String EXTENSION_TYPE = "x509Extension";

    private static final String EXTENSION_KEY = "key";
    private static final String EXTENSION_VALUE = "value";

    @Override
    public boolean matches(X509Certificate attestationCertificate, JsonNode parameters) {
        String matchKey = parameters.get(EXTENSION_KEY).asText();
        JsonNode matchValue = parameters.get(EXTENSION_VALUE);
        byte[] extensionValue = attestationCertificate.getExtensionValue(matchKey);
        if (extensionValue != null) {
            if (matchValue == null || matchValue.asText().equals(Strings.fromByteArray(extensionValue))) {
                return true;
            }
        }
        return false;
    }
}
