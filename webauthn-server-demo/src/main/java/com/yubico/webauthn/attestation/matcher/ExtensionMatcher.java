// Copyright (c) 2015-2018, Yubico AB
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

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
public final class ExtensionMatcher implements DeviceMatcher {
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
        try {
          final ASN1Primitive value = ASN1Primitive.fromByteArray(extensionValue);

          if (matchValue.isObject()) {
            if (matchTypedValue(matchKey, matchValue, value)) {
              return true;
            }
          } else if (matchValue.isTextual()) {
            if (matchStringValue(matchKey, matchValue, value)) return true;
          }
        } catch (IOException e) {
          log.error(
              "Failed to parse extension value as ASN1: {}",
              new ByteArray(extensionValue).getHex(),
              e);
        }
      }
    }
    return false;
  }

  private boolean matchStringValue(String matchKey, JsonNode matchValue, ASN1Primitive value) {
    if (value instanceof DEROctetString) {
      final String readValue = new String(((DEROctetString) value).getOctets(), CHARSET);
      return matchValue.asText().equals(readValue);
    } else {
      log.debug("Expected text string value for extension {}, was: {}", matchKey, value);
      return false;
    }
  }

  private boolean matchTypedValue(String matchKey, JsonNode matchValue, ASN1Primitive value) {
    final String extensionValueType = matchValue.get(EXTENSION_VALUE_TYPE).textValue();
    switch (extensionValueType) {
      case EXTENSION_VALUE_TYPE_HEX:
        return matchHex(matchKey, matchValue, value);

      default:
        throw new IllegalArgumentException(
            String.format(
                "Unknown extension value type \"%s\" for extension \"%s\"",
                extensionValueType, matchKey));
    }
  }

  private boolean matchHex(String matchKey, JsonNode matchValue, ASN1Primitive value) {
    final String matchValueString = matchValue.get(EXTENSION_VALUE_VALUE).textValue();
    final ByteArray matchBytes;
    try {
      matchBytes = ByteArray.fromHex(matchValueString);
    } catch (HexException e) {
      throw new IllegalArgumentException(
          String.format("Bad hex value in extension %s: %s", matchKey, matchValueString));
    }

    final ASN1Primitive innerValue;
    if (value instanceof DEROctetString) {
      try {
        innerValue = ASN1Primitive.fromByteArray(((DEROctetString) value).getOctets());
      } catch (IOException e) {
        log.debug("Failed to parse {} extension value as ASN1: {}", matchKey, value);
        return false;
      }
    } else {
      log.debug("Expected nested bit string value for extension {}, was: {}", matchKey, value);
      return false;
    }

    if (innerValue instanceof DEROctetString) {
      final ByteArray readBytes = new ByteArray(((DEROctetString) innerValue).getOctets());
      return matchBytes.equals(readBytes);
    } else {
      log.debug("Expected nested bit string value for extension {}, was: {}", matchKey, value);
      return false;
    }
  }
}
