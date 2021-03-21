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

package com.yubico.webauthn.attestation;

import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

public interface TrustResolver {

  /**
   * Alias of <code>resolveTrustAnchor(attestationCertificate, Collections.emptyList())</code>.
   *
   * @see #resolveTrustAnchor(X509Certificate, List)
   */
  default Optional<X509Certificate> resolveTrustAnchor(X509Certificate attestationCertificate) {
    return resolveTrustAnchor(attestationCertificate, Collections.emptyList());
  }

  /**
   * Resolve a trusted root anchor for the given attestation certificate and certificate chain
   *
   * @param attestationCertificate The attestation certificate
   * @param caCertificateChain Zero or more certificates, of which the first has signed <code>
   *     attestationCertificate</code> and each of the remaining certificates has signed the
   *     certificate preceding it.
   * @return A trusted root certificate from which there is a signature path to <code>
   *     attestationCertificate</code>, if one exists.
   */
  Optional<X509Certificate> resolveTrustAnchor(
      X509Certificate attestationCertificate, List<X509Certificate> caCertificateChain);
}
