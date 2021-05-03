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

package com.yubico.webauthn.attestation.resolver;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.yubico.internal.util.CertificateParser;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Principal;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Optional;
import org.junit.Test;
import org.mockito.ArgumentMatchers;

public class SimpleTrustResolverTest {

  private static final String METADATA_JSON =
      "{\"identifier\":\"foobar\",\"version\":1,\"trustedCertificates\":[\"-----BEGIN CERTIFICATE-----\\nMIIDHjCCAgagAwIBAgIEG1BT9zANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZ\\ndWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAw\\nMDBaGA8yMDUwMDkwNDAwMDAwMFowLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290\\nIENBIFNlcmlhbCA0NTcyMDA2MzEwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\\nAoIBAQC/jwYuhBVlqaiYWEMsrWFisgJ+PtM91eSrpI4TK7U53mwCIawSDHy8vUmk\\n5N2KAj9abvT9NP5SMS1hQi3usxoYGonXQgfO6ZXyUA9a+KAkqdFnBnlyugSeCOep\\n8EdZFfsaRFtMjkwz5Gcz2Py4vIYvCdMHPtwaz0bVuzneueIEz6TnQjE63Rdt2zbw\\nnebwTG5ZybeWSwbzy+BJ34ZHcUhPAY89yJQXuE0IzMZFcEBbPNRbWECRKgjq//qT\\n9nmDOFVlSRCt2wiqPSzluwn+v+suQEBsUjTGMEd25tKXXTkNW21wIWbxeSyUoTXw\\nLvGS6xlwQSgNpk2qXYwf8iXg7VWZAgMBAAGjQjBAMB0GA1UdDgQWBBQgIvz0bNGJ\\nhjgpToksyKpP9xv9oDAPBgNVHRMECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjAN\\nBgkqhkiG9w0BAQsFAAOCAQEAjvjuOMDSa+JXFCLyBKsycXtBVZsJ4Ue3LbaEsPY4\\nMYN/hIQ5ZM5p7EjfcnMG4CtYkNsfNHc0AhBLdq45rnT87q/6O3vUEtNMafbhU6kt\\nhX7Y+9XFN9NpmYxr+ekVY5xOxi8h9JDIgoMP4VB1uS0aunL1IGqrNooL9mmFnL2k\\nLVVee6/VR6C5+KSTCMCWppMuJIZII2v9o4dkoZ8Y7QRjQlLfYzd3qGtKbw7xaF1U\\nsG/5xUb/Btwb2X2g4InpiB/yt/3CpQXpiWX/K4mBvUKiGn05ZsqeY1gx4g0xLBqc\\nU9psmyPzK+Vsgw2jeRQ5JlKDyqE0hebfC1tvFu0CCrJFcw==\\n-----END CERTIFICATE-----\"],\"vendorInfo\":{\"name\":\"Yubico\",\"url\":\"https://yubico.com\",\"imageUrl\":\"https://developers.yubico.com/U2F/Images/yubico.png\"},\"devices\":[{\"displayName\":\"YubiKey NEO/NEO-n\",\"deviceId\":\"1.3.6.1.4.1.41482.1.2\",\"deviceUrl\":\"https://www.yubico.com/products/yubikey-hardware/yubikey-neo/\",\"imageUrl\":\"https://developers.yubico.com/U2F/Images/NEO.png\",\"selectors\":[{\"type\":\"x509Extension\",\"parameters\":{\"key\":\"1.3.6.1.4.1.41482.1.2\"}}]}]  }";
  private static final String ATTESTATION_CERT =
      "MIICGzCCAQWgAwIBAgIEdaP2dTALBgkqhkiG9w0BAQswLjEsMCoGA1UEAxMjWXViaWNvIFUyRiBSb290IENBIFNlcmlhbCA0NTcyMDA2MzEwIBcNMTQwODAxMDAwMDAwWhgPMjA1MDA5MDQwMDAwMDBaMCoxKDAmBgNVBAMMH1l1YmljbyBVMkYgRUUgU2VyaWFsIDE5NzM2Nzk3MzMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQZo35Damtpl81YdmcbhEuXKAr7xDcQzAy5n3ftAAhtBbu8EeGU4ynfSgLonckqX6J2uXLBppTNE3v2bt+Yf8MLoxIwEDAOBgorBgEEAYLECgECBAAwCwYJKoZIhvcNAQELA4IBAQG9LbiNPgs0sQYOHAJcg+lMk+HCsiWRlYVnbT4I/5lnqU907vY17XYAORd432bU3Nnhsbkvjz76kQJGXeNAF4DPANGGlz8JU+LNEVE2PWPGgEM0GXgB7mZN5Sinfy1AoOdO+3c3bfdJQuXlUxHbo+nDpxxKpzq9gr++RbokF1+0JBkMbaA/qLYL4WdhY5NvaOyMvYpO3sBxlzn6FcP67hlotGH1wU7qhCeh+uur7zDeAWVh7c4QtJOXHkLJQfV3Z7ZMvhkIA6jZJAX99hisABU/SSa5DtgX7AfsHwa04h69AAAWDUzSk3HgOXbUd1FaSOPdlVFkG2N2JllFHykyO3zO";

  private final SimpleTrustResolver resolver = SimpleTrustResolver.fromMetadataJson(METADATA_JSON);

  public SimpleTrustResolverTest() throws IOException, CertificateException {}

  @Test
  public void testResolve() throws Exception {
    X509Certificate certificate = CertificateParser.parseDer(ATTESTATION_CERT);

    Optional<X509Certificate> trustAnchor = resolver.resolveTrustAnchor(certificate);

    assertTrue(trustAnchor.isPresent());
    assertEquals(
        "CN=Yubico U2F Root CA Serial 457200631", trustAnchor.get().getSubjectDN().getName());
  }

  @Test
  public void resolveReturnsEmptyOnUntrustedSignature() throws Exception {
    X509Certificate cert = mock(X509Certificate.class);
    doThrow(new SignatureException("Forced failure")).when(cert).verify(ArgumentMatchers.any());
    Principal issuerDN = mock(Principal.class);
    when(issuerDN.getName()).thenReturn("CN=Yubico U2F Root CA Serial 457200631");
    when(cert.getIssuerDN()).thenReturn(issuerDN);

    assertEquals(Optional.empty(), resolver.resolveTrustAnchor(cert));
  }

  private void resolveThrowsExceptionOnUnexpectedError(Exception thrownException) throws Exception {
    X509Certificate cert = mock(X509Certificate.class);
    doThrow(thrownException).when(cert).verify(ArgumentMatchers.any());
    Principal issuerDN = mock(Principal.class);
    when(issuerDN.getName()).thenReturn("CN=Yubico U2F Root CA Serial 457200631");
    when(cert.getIssuerDN()).thenReturn(issuerDN);

    resolver.resolveTrustAnchor(cert);
  }

  @Test(expected = RuntimeException.class)
  public void resolveThrowsExceptionOnCertificateException() throws Exception {
    resolveThrowsExceptionOnUnexpectedError(new CertificateException("Forced failure"));
  }

  @Test(expected = RuntimeException.class)
  public void resolveThrowsExceptionOnNoSuchAlgorithmException() throws Exception {
    resolveThrowsExceptionOnUnexpectedError(new NoSuchAlgorithmException("Forced failure"));
  }

  @Test(expected = RuntimeException.class)
  public void resolveThrowsExceptionOnInvalidKeyException() throws Exception {
    resolveThrowsExceptionOnUnexpectedError(new InvalidKeyException("Forced failure"));
  }

  @Test(expected = RuntimeException.class)
  public void resolveThrowsExceptionOnNoSuchProviderException() throws Exception {
    resolveThrowsExceptionOnUnexpectedError(new NoSuchProviderException("Forced failure"));
  }
}
