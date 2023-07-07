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

package com.yubico.webauthn;

import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import java.util.Optional;
import java.util.Set;

/**
 * An abstraction of database lookups needed by this library.
 *
 * <p>This is used by {@link RelyingParty} to look up credentials and credential IDs.
 *
 * <p>Unlike {@link CredentialRepository}, this interface does not require support for usernames.
 */
public interface CredentialRepositoryV2<C extends CredentialRecord> {

  /**
   * Get the credential IDs of all credentials registered to the user with the given user handle.
   *
   * <p>After a successful registration ceremony, the {@link RegistrationResult#getKeyId()} method
   * returns a value suitable for inclusion in this set.
   *
   * @return a {@link Set} containing one {@link PublicKeyCredentialDescriptor} for each credential
   *     registered to the given user. The set MUST NOT be null, but MAY be empty if the user does
   *     not exist or has no credentials.
   */
  Set<PublicKeyCredentialDescriptor> getCredentialIdsForUserHandle(ByteArray userHandle);

  /**
   * Look up the public key, backup flags and current signature count for the given credential
   * registered to the given user.
   *
   * <p>The returned {@link RegisteredCredential} is not expected to be long-lived. It may be read
   * directly from a database or assembled from other components.
   *
   * @return a {@link RegisteredCredential} describing the current state of the registered
   *     credential with credential ID <code>credentialId</code>, if any. If the credential does not
   *     exist or is registered to a different user handle than <code>userHandle</code>, return
   *     {@link Optional#empty()}.
   */
  Optional<C> lookup(ByteArray credentialId, ByteArray userHandle);

  /**
   * Check whether any credential exists with the given credential ID, regardless of what user it is
   * registered to.
   *
   * <p>This is used to refuse registration of duplicate credential IDs.
   *
   * @return <code>true</code> if and only if the credential database contains at least one
   *     credential with the given credential ID.
   */
  boolean credentialIdExists(ByteArray credentialId);
}
