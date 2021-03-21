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

import com.yubico.internal.util.CollectionUtil;
import com.yubico.webauthn.attestation.Attestation;
import com.yubico.webauthn.attestation.AttestationResolver;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;

/**
 * An {@link AttestationResolver} whose {@link #resolve(X509Certificate, List)} method calls {@link
 * AttestationResolver#resolve(X509Certificate, List)} on each of the subordinate {@link
 * AttestationResolver}s in turn, and returns the first non-<code>null</code> result.
 */
public final class CompositeAttestationResolver implements AttestationResolver {

  private final List<AttestationResolver> resolvers;

  public CompositeAttestationResolver(List<AttestationResolver> resolvers) {
    this.resolvers = CollectionUtil.immutableList(resolvers);
  }

  @Override
  public Optional<Attestation> resolve(
      X509Certificate attestationCertificate, List<X509Certificate> certificateChain) {
    for (AttestationResolver resolver : resolvers) {
      Optional<Attestation> result = resolver.resolve(attestationCertificate, certificateChain);
      if (result.isPresent()) {
        return result;
      }
    }
    return Optional.empty();
  }

  /** Delegates to the first subordinate resolver, or throws an exception if there is none. */
  @Override
  public Attestation untrustedFromCertificate(X509Certificate attestationCertificate) {
    if (resolvers.isEmpty()) {
      throw new UnsupportedOperationException("Cannot do this without any sub-resolver.");
    } else {
      return resolvers.get(0).untrustedFromCertificate(attestationCertificate);
    }
  }
}
