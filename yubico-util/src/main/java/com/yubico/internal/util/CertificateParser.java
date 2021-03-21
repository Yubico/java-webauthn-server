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

package com.yubico.internal.util;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

public class CertificateParser {
  //    private static final Provider BC_PROVIDER = new BouncyCastleProvider();
  private static final Base64.Decoder BASE64_DECODER = Base64.getDecoder();

  private static final List<String> FIXSIG =
      Arrays.asList(
          "CN=Yubico U2F EE Serial 776137165",
          "CN=Yubico U2F EE Serial 1086591525",
          "CN=Yubico U2F EE Serial 1973679733",
          "CN=Yubico U2F EE Serial 13503277888",
          "CN=Yubico U2F EE Serial 13831167861",
          "CN=Yubico U2F EE Serial 14803321578");

  private static final int UNUSED_BITS_BYTE_INDEX_FROM_END = 257;

  public static X509Certificate parsePem(String pemEncodedCert) throws CertificateException {
    return parseDer(
        pemEncodedCert
            .replaceAll("-----BEGIN CERTIFICATE-----", "")
            .replaceAll("-----END CERTIFICATE-----", "")
            .replaceAll("\n", ""));
  }

  public static X509Certificate parseDer(String base64DerEncodedCert) throws CertificateException {
    return parseDer(BASE64_DECODER.decode(base64DerEncodedCert));
  }

  public static X509Certificate parseDer(byte[] derEncodedCert) throws CertificateException {
    return parseDer(new ByteArrayInputStream(derEncodedCert));
  }

  public static X509Certificate parseDer(InputStream is) throws CertificateException {
    X509Certificate cert =
        (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(is);
    // Some known certs have an incorrect "unused bits" value, which causes problems on newer
    // versions of BouncyCastle.
    if (FIXSIG.contains(cert.getSubjectDN().getName())) {
      byte[] encoded = cert.getEncoded();

      if (encoded.length >= UNUSED_BITS_BYTE_INDEX_FROM_END) {
        encoded[encoded.length - UNUSED_BITS_BYTE_INDEX_FROM_END] =
            0; // Fix the "unused bits" field (should always be 0).
      } else {
        throw new IllegalArgumentException(
            String.format(
                "Expected DER encoded cert to be at least %d bytes, was %d: %s",
                UNUSED_BITS_BYTE_INDEX_FROM_END, encoded.length, cert));
      }

      cert =
          (X509Certificate)
              CertificateFactory.getInstance("X.509")
                  .generateCertificate(new ByteArrayInputStream(encoded));
    }
    return cert;
  }
}
