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
 */
public interface CredentialRepositoryV2 {
  /**
   * Get the credential IDs of all credentials registered to the given user.
   *
   * <p>After a successful registration ceremony, the {@link RegistrationResult#getKeyId()} method
   * returns a value suitable for inclusion in this set.
   *
   * <p>This method is invoked from {@link
   * RelyingParty#startRegistration(StartRegistrationOptions)}. In this case, it is passed the
   * UserIdentity specified in {@link StartRegistrationOptions#getUser()}.
   *
   * <p>Additionally, this method is invoked from {@link
   * RelyingParty#startAssertion(StartAssertionOptions)} if {@link StartAssertionOptions#getUser()}
   * is present, with that UserIdentity. If {@link StartAssertionOptions#getUsername()} or {@link
   * StartAssertionOptions#getUserHandle()} are present, it is invoked with the return value of
   * {@link #findUserByUsername(String)} or {@link #findUserByUserHandle(ByteArray)} respectively,
   * instead.
   */
  @NonNull
  Set<PublicKeyCredentialDescriptor> getCredentialIdsForUser(@NonNull UserIdentity user);

  /**
   * Builds a UserIdentity corresponding to the given username.
   *
   * <p>This is only invoked from {@link RelyingParty#startAssertion(StartAssertionOptions)}, and
   * only if {@link StartAssertionOptions#getUsername()} is present.
   */
  @NonNull
  Optional<UserIdentity> findUserByUsername(@NonNull String username);

  /**
   * Builds a UserIdentity corresponding to the given user handle.
   *
   * <p>This is invoked from {@link RelyingParty#startAssertion(StartAssertionOptions)} only if
   * {@link StartAssertionOptions#getUserHandle()} is present.
   *
   * <p>Additionally, when authenticating using a discoverable credential (passkey), i.e., if none
   * of {@link StartAssertionOptions#getUser()}, {@link StartAssertionOptions#getUsername()} and
   * {@link StartAssertionOptions#getUserHandle()} are present, this is invoked from {@link
   * RelyingParty#finishAssertion(FinishAssertionOptions)}, with the credential's user handle.
   */
  @NonNull
  Optional<UserIdentity> findUserByUserHandle(@NonNull ByteArray userHandle);

  /**
   * Look up the public key and stored signature count for the given credential registered to the
   * given user.
   *
   * <p>The returned {@link RegisteredCredential} is not expected to be long-lived. It may be read
   * directly from a database or assembled from other components.
   */
  @NonNull
  Optional<RegisteredCredential> lookup(
      @NonNull ByteArray credentialId, @NonNull UserIdentity user);

  /**
   * Look up all credentials with the given credential ID, regardless of what user they're
   * registered to.
   *
   * <p>This is used to refuse registration of duplicate credential IDs. Therefore, under normal
   * circumstances this method should only return zero or one credential (this is an expected
   * consequence, not an interface requirement).
   */
  @NonNull
  Set<RegisteredCredential> lookupAll(@NonNull ByteArray credentialId);
}
