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
import com.yubico.webauthn.data.UserIdentity;
import java.util.Optional;
import java.util.Set;
import lombok.NonNull;

/**
 * An abstraction of the database lookups needed by this library.
 *
 * <p>This is used by {@link RelyingParty} to look up credentials, usernames and user handles from
 * usernames, user handles and credential IDs.
 *
 * @deprecated this interface is provided for backwards compatibility; use {@link
 *     CredentialRepositoryV2} instead
 */
@Deprecated
public interface CredentialRepository extends CredentialRepositoryV2 {

  /**
   * Get the credential IDs of all credentials registered to the user with the given username.
   *
   * <p>After a successful registration ceremony, the {@link RegistrationResult#getKeyId()} method
   * returns a value suitable for inclusion in this set.
   */
  @NonNull
  Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(@NonNull String username);

  /**
   * Get the user handle corresponding to the given username - the inverse of {@link
   * #getUsernameForUserHandle(ByteArray)}.
   *
   * <p>Used to look up the user handle based on the username, for authentication ceremonies where
   * the username is already given.
   */
  @NonNull
  Optional<ByteArray> getUserHandleForUsername(@NonNull String username);

  /**
   * Get the username corresponding to the given user handle - the inverse of {@link
   * #getUserHandleForUsername(String)}.
   *
   * <p>Used to look up the username based on the user handle, for username-less authentication
   * ceremonies.
   */
  @NonNull
  Optional<String> getUsernameForUserHandle(@NonNull ByteArray userHandle);

  /**
   * Look up the public key and stored signature count for the given credential registered to the
   * given user.
   *
   * <p>The returned {@link RegisteredCredential} is not expected to be long-lived. It may be read
   * directly from a database or assembled from other components.
   */
  @NonNull
  Optional<RegisteredCredential> lookup(
      @NonNull ByteArray credentialId, @NonNull ByteArray userHandle);

  /// map the methods of the new interface to the methods on the old interface

  @Override
  @NonNull
  default Set<PublicKeyCredentialDescriptor> getCredentialIdsForUser(@NonNull UserIdentity user) {
    return getCredentialIdsForUsername(user.getName());
  }

  @Override
  @NonNull
  default Optional<UserIdentity> findUserByUsername(@NonNull String username) {
    return getUserHandleForUsername(username)
        .map(uh -> UserIdentity.builder().name(username).displayName(username).id(uh).build());
  }

  @Override
  @NonNull
  default Optional<UserIdentity> findUserByUserHandle(@NonNull ByteArray userHandle) {
    return getUsernameForUserHandle(userHandle)
        .map(un -> UserIdentity.builder().name(un).displayName(un).id(userHandle).build());
  }

  @Override
  @NonNull
  default Optional<RegisteredCredential> lookup(
      @NonNull ByteArray credentialId, @NonNull UserIdentity identity) {
    return lookup(credentialId, identity.getId());
  }
}
