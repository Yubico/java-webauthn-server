/* Copyright 2015 Yubico */

package com.yubico.webauthn.attestation.matcher;

import com.fasterxml.jackson.databind.JsonNode;
import com.yubico.webauthn.attestation.DeviceMatcher;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.exception.HexException;
import java.io.IOException;
import java.nio.charset.Charset;
import java.security.cert.X509Certificate;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.DEROctetString;

@Slf4j
public class ExtensionMatcher implements DeviceMatcher {
    private static final Charset CHARSET = Charset.forName("UTF-8");

    public static final String SELECTOR_TYPE = "x509Extension";

    private static final String EXTENSION_KEY = "key";
    private static final String EXTENSION_VALUE = "value";
    private static final String EXTENSION_VALUE_TYPE = "type";
    private static final String EXTENSION_VALUE_VALUE = "value";
    private static final String EXTENSION_VALUE_TYPE_HEX = "hex";

    @Override
    public boolean matches(X509Certificate attestationCertificate, JsonNode parameters) {
        String matchKey = parameters.get(EXTENSION_KEY).asText();
        JsonNode matchValue = parameters.get(EXTENSION_VALUE);
        byte[] extensionValue = attestationCertificate.getExtensionValue(matchKey);
        if (extensionValue != null) {
            if (matchValue == null) {
                return true;
            } else {
                //TODO: Handle long lengths? Verify length?
                try {
                    final ASN1Primitive value = ASN1Primitive.fromByteArray(extensionValue);

                    if (matchValue.isObject()) {
                        final String extensionValueType = matchValue.get(EXTENSION_VALUE_TYPE).textValue();
                        switch (extensionValueType) {
                            case EXTENSION_VALUE_TYPE_HEX:
                                final ASN1Primitive innerValue;

                                if (value instanceof DEROctetString) {
                                    innerValue = ASN1Primitive.fromByteArray(((DEROctetString) value).getOctets());
                                } else {
                                    log.debug("Expected ASN.1 bit string value for extension {}, was: {}", matchKey, value);
                                    return false;
                                }

                                final String matchValueString = matchValue.get(EXTENSION_VALUE_VALUE).textValue();
                                final ByteArray matchBytes;
                                try {
                                    matchBytes = ByteArray.fromHex(matchValueString);
                                } catch (HexException e) {
                                    throw new IllegalArgumentException(String.format(
                                        "Bad hex value in extension %s: %s",
                                        matchKey,
                                        matchValueString
                                    ));
                                }

                                final ByteArray readBytes = new ByteArray(((DEROctetString) innerValue).getOctets());
                                if (matchBytes.equals(readBytes)) {
                                    return true;
                                }
                                break;

                            default:
                                throw new IllegalArgumentException(String.format(
                                    "Unknown extension value type \"%s\" for extension \"%s\"",
                                    extensionValueType,
                                    matchKey
                                ));
                        }
                    } else if (matchValue.isTextual()) {
                        if (value instanceof DEROctetString) {
                            final String readValue = new String(((DEROctetString) value).getOctets(), CHARSET);
                            if (matchValue.asText().equals(readValue)) {
                                return true;
                            }
                        } else {
                            log.debug("Expected text string value for extension {}, was: {}", matchKey, value);
                        }
                    }
                } catch (IOException e) {
                    log.error("Failed to parse extension value as ASN1: {}", new ByteArray(extensionValue).getHex(), e);
                }
            }
        }
        return false;
    }
}
