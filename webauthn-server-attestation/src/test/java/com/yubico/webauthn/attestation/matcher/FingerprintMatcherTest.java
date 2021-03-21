// Copyright (c) 2018, Yubico AB
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

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.BooleanNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.TextNode;
import com.google.common.hash.Hashing;
import com.yubico.internal.util.CertificateParser;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import org.junit.Test;

public class FingerprintMatcherTest {

  private static final String ATTESTATION_CERT =
      "MIICGzCCAQWgAwIBAgIEdaP2dTALBgkqhkiG9w0BAQswLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290IENBIFNlcmlhbCA0NTcyMDA2MzEwIBcNMTQwODAxMDAwMDAwWhgPMjA1MDA5MDQwMDAwMDBaMCoxKDAmBgNVBAMMH1l1YmljbyBVMkYgRUUgU2VyaWFsIDE5NzM2Nzk3MzMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQZo35Damtpl81YdmcbhEuXKAr7xDcQzAy5n3ftAAhtBbu8EeGU4ynfSgLonckqX6J2uXLBppTNE3v2bt+Yf8MLoxIwEDAOBgorBgEEAYLECgECBAAwCwYJKoZIhvcNAQELA4IBAQG9LbiNPgs0sQYOHAJcg+lMk+HCsiWRlYVnbT4I/5lnqU907vY17XYAORd432bU3Nnhsbkvjz76kQJGXeNAF4DPANGGlz8JU+LNEVE2PWPGgEM0GXgB7mZN5Sinfy1AoOdO+3c3bfdJQuXlUxHbo+nDpxxKpzq9gr++RbokF1+0JBkMbaA/qLYL4WdhY5NvaOyMvYpO3sBxlzn6FcP67hlotGH1wU7qhCeh+uur7zDeAWVh7c4QtJOXHkLJQfV3Z7ZMvhkIA6jZJAX99hisABU/SSa5DtgX7AfsHwa04h69AAAWDUzSk3HgOXbUd1FaSOPdlVFkG2N2JllFHykyO3zO";

  @Test
  public void matchesIsFalseForNonArrayFingerprints() {
    JsonNode parameters = mock(JsonNode.class);
    when(parameters.get("fingerprints")).thenReturn(BooleanNode.TRUE);

    assertFalse(new FingerprintMatcher().matches(mock(X509Certificate.class), parameters));
  }

  @Test
  public void matchesIsFalseIfNoFingerprintMatches() throws CertificateException {
    final X509Certificate cert = CertificateParser.parsePem(ATTESTATION_CERT);

    ArrayNode fingerprints = new ArrayNode(JsonNodeFactory.instance);
    fingerprints.add(new TextNode("foo"));
    fingerprints.add(new TextNode("bar"));

    JsonNode parameters = mock(JsonNode.class);
    when(parameters.get("fingerprints")).thenReturn(fingerprints);

    assertFalse(new FingerprintMatcher().matches(cert, parameters));
  }

  @Test
  public void matchesIsTrueIfSomeFingerprintMatches() throws CertificateException {
    final X509Certificate cert = CertificateParser.parsePem(ATTESTATION_CERT);
    final String fingerprint = Hashing.sha1().hashBytes(cert.getEncoded()).toString().toLowerCase();

    ArrayNode fingerprints = new ArrayNode(JsonNodeFactory.instance);
    fingerprints.add(new TextNode("foo"));
    fingerprints.add(new TextNode(fingerprint));

    JsonNode parameters = mock(JsonNode.class);
    when(parameters.get("fingerprints")).thenReturn(fingerprints);

    assertTrue(new FingerprintMatcher().matches(cert, parameters));
  }
}
