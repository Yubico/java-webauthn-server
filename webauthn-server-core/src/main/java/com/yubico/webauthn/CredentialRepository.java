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
 * An abstraction of the database lookups needed by this library.
 *
 * <p>
 * This is used by {@link RelyingParty} to look up credentials, usernames and user handles from usernames, user handles
 * and credential IDs.
 * </p>
 */
public interface CredentialRepository {

    /**
     * Get the credential IDs of all credentials registered to the user with the given username.
     */
    Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username);

    /**
     * Get the user handle corresponding to the given username - the inverse of {@link
     * #getUsernameForUserHandle(ByteArray)}.
     */
    Optional<ByteArray> getUserHandleForUsername(String username);

    /**
     * Get the username corresponding to the given user handle - the inverse of {@link
     * #getUserHandleForUsername(String)}.
     */
    Optional<String> getUsernameForUserHandle(ByteArray userHandle);

    /**
     * Look up the public key and stored signature count for the given credential registered to the given user.
     *
     * <p>
     * The returned {@link RegisteredCredential} is not expected to be long-lived. It may be read directly from a
     * database or assembled from other components.
     * </p>
     */
    Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle);

    /**
     * Look up all credentials with the given credential ID, regardless of what user they're registered to.
     *
     * <p>
     * This is used to refuse registration of duplicate credential IDs. Therefore, under normal circumstances this
     * method should only return zero or one credential (this is an expected consequence, not an interface
     * requirement).
     * </p>
     */
    Set<RegisteredCredential> lookupAll(ByteArray credentialId);

}
