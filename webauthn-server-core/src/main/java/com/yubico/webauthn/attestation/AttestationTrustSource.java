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

import com.yubico.webauthn.data.ByteArray;
import java.security.cert.CertStore;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/** Abstraction of a repository which can look up trust roots for authenticator attestation. */
public interface AttestationTrustSource {

  /**
   * Attempt to look up attestation trust roots for an authenticator AAGUID.
   *
   * @param aaguid an authenticator AAGUID
   * @return Attestation metadata, if any is available. If no trusted attestation roots for this
   *     AAGUID are found, return an empty set. Implementations MAY also return a static set of
   *     trust anchors regardless of the <code>aaguid</code> argument.
   */
  Set<X509Certificate> findTrustRoots(ByteArray aaguid);

  /**
   * Attempt to look up attestation trust roots for an attestation certificate chain.
   *
   * @param attestationCertificateChain a certificate chain, where each certificate in the list
   *     should be signed by the subsequent certificate. The trust anchor is typically not included
   *     in this certificate chain.
   * @return A set of trusted attestation root certificates, if any are available. If the
   *     certificate chain is empty, or if no trust roots for this certificate chain are found,
   *     return an empty set. Implementations MAY also return a static set of trust anchors
   *     regardless of the <code>attestationCertificateChain</code> argument.
   */
  Set<X509Certificate> findTrustRoots(List<X509Certificate> attestationCertificateChain);

  /**
   * Retrieve a {@link CertStore} containing additional certificates and/or CRLs required for
   * validating the given certificate chain.
   *
   * <p>The default implementation always returns {@link Optional#empty()}. This method is most
   * likely useful for tests, since most real-world certificates will likely include the X.509 CRL
   * distribution points extension, in which case an additional {@link CertStore} is not necessary.
   *
   * @param attestationCertificateChain a certificate chain, where each certificate in the list
   *     should be signed by the subsequent certificate. The trust anchor is typically not included
   *     in this certificate chain.
   * @return a {@link CertStore} containing any additional certificates and/or CRLs required for
   *     validating the certificate chain, if applicable.
   */
  default Optional<CertStore> getCertStore(List<X509Certificate> attestationCertificateChain) {
    return Optional.empty();
  }
}
