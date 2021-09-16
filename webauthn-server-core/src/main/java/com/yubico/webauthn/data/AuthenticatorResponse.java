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

package com.yubico.webauthn.data;

import com.fasterxml.jackson.annotation.JsonIgnore;

/**
 * Authenticators respond to Relying Party requests by returning an object derived from the {@link
 * AuthenticatorResponse} interface.
 *
 * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#authenticatorresponse">§5.2.
 *     Authenticator Responses (interface AuthenticatorResponse) </a>
 */
public interface AuthenticatorResponse {

  /**
   * The authenticator data returned by the authenticator. See <a
   * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-authenticator-data">§6.1
   * Authenticator Data</a>.
   */
  ByteArray getAuthenticatorData();

  /** {@link #getAuthenticatorData()} parsed as a domain object. */
  @JsonIgnore
  default AuthenticatorData getParsedAuthenticatorData() {
    return new AuthenticatorData(getAuthenticatorData());
  }

  /**
   * The JSON-serialized client data (see <a
   * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#dictionary-client-data">§5.10.1
   * Client Data Used in WebAuthn Signatures</a> (dictionary {@link CollectedClientData})) passed to
   * the authenticator by the client in the call to either <code>navigator.credentials.create()
   * </code> or <code>navigator.credentials.get()</code>. The exact JSON serialization MUST be
   * preserved, as the hash of the serialized client data has been computed over it.
   */
  ByteArray getClientDataJSON();

  /** {@link #getClientDataJSON()} parsed as a domain object. */
  @JsonIgnore
  CollectedClientData getClientData();
}
