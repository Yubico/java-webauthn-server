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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.yubico.webauthn.data.AuthenticatorAssertionExtensionOutputs;
import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.AuthenticatorData;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions;
import com.yubico.webauthn.data.UserIdentity;
import java.util.Optional;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NonNull;
import lombok.Value;

/** The result of a call to {@link RelyingParty#finishAssertion(FinishAssertionOptions)}. */
@Value
public class AssertionResult {

  /** <code>true</code> if the assertion was verified successfully. */
  private final boolean success;

  @JsonProperty
  @Getter(AccessLevel.NONE)
  private final PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs>
      credentialResponse;

  /**
   * The {@link RegisteredCredential} that was returned by {@link
   * CredentialRepository#lookup(ByteArray, ByteArray)} and whose public key was used to
   * successfully verify the assertion signature.
   *
   * <p>NOTE: The {@link RegisteredCredential#getSignatureCount() signature count} in this object
   * will reflect the signature counter state <i>before</i> the assertion operation, not the new
   * counter value. When updating your database state, use the signature counter from {@link
   * #getSignatureCount()} instead.
   */
  private final RegisteredCredential credential;

  /**
   * The username of the authenticated user.
   *
   * @see #getUserHandle()
   */
  @NonNull private final String username;

  /**
   * <code>true</code> if and only if at least one of the following is true:
   *
   * <ul>
   *   <li>The {@link AuthenticatorData#getSignatureCounter() signature counter value} in the
   *       assertion was strictly greater than {@link RegisteredCredential#getSignatureCount() the
   *       stored one}.
   *   <li>The {@link AuthenticatorData#getSignatureCounter() signature counter value} in the
   *       assertion and {@link RegisteredCredential#getSignatureCount() the stored one} were both
   *       zero.
   * </ul>
   *
   * @see <a
   *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-authenticator-data">§6.1.
   *     Authenticator Data</a>
   * @see AuthenticatorData#getSignatureCounter()
   * @see RegisteredCredential#getSignatureCount()
   * @see com.yubico.webauthn.RelyingParty.RelyingPartyBuilder#validateSignatureCounter(boolean)
   */
  private final boolean signatureCounterValid;

  @JsonCreator
  AssertionResult(
      @JsonProperty("success") boolean success,
      @NonNull @JsonProperty("credentialResponse")
          PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs>
              credentialResponse,
      @NonNull @JsonProperty("credential") RegisteredCredential credential,
      @NonNull @JsonProperty("username") String username,
      @JsonProperty("signatureCounterValid") boolean signatureCounterValid) {
    this.success = success;
    this.credentialResponse = credentialResponse;
    this.credential = credential;
    this.username = username;
    this.signatureCounterValid = signatureCounterValid;
  }

  /**
   * The <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#credential-id">credential
   * ID</a> of the credential used for the assertion.
   *
   * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#credential-id">Credential
   *     ID</a>
   * @see PublicKeyCredentialRequestOptions#getAllowCredentials()
   * @deprecated Use {@link #getCredential()}.{@link RegisteredCredential#getCredentialId()
   *     getCredentialId()} instead.
   */
  @Deprecated
  @JsonIgnore
  public ByteArray getCredentialId() {
    return credential.getCredentialId();
  }

  /**
   * The <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#user-handle">user handle</a>
   * of the authenticated user.
   *
   * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#user-handle">User Handle</a>
   * @see UserIdentity#getId()
   * @see #getUsername()
   * @deprecated Use {@link #getCredential()}.{@link RegisteredCredential#getUserHandle()
   *     getUserHandle()} instead.
   */
  @Deprecated
  @JsonIgnore
  public ByteArray getUserHandle() {
    return credential.getUserHandle();
  }

  /**
   * The new <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#signcount">signature
   * count</a> of the credential used for the assertion.
   *
   * <p>You should update this value in your database.
   *
   * @see AuthenticatorData#getSignatureCounter()
   */
  @JsonIgnore
  public long getSignatureCount() {
    return credentialResponse.getResponse().getParsedAuthenticatorData().getSignatureCounter();
  }

  /**
   * The <a
   * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#client-extension-output">client
   * extension outputs</a>, if any.
   *
   * <p>This is present if and only if at least one extension output is present in the return value.
   *
   * @see <a
   *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-client-extension-processing">§9.4.
   *     Client Extension Processing</a>
   * @see ClientAssertionExtensionOutputs
   * @see #getAuthenticatorExtensionOutputs() ()
   */
  @JsonIgnore
  public Optional<ClientAssertionExtensionOutputs> getClientExtensionOutputs() {
    return Optional.of(credentialResponse.getClientExtensionResults())
        .filter(ceo -> !ceo.getExtensionIds().isEmpty());
  }

  /**
   * The <a
   * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#authenticator-extension-output">authenticator
   * extension outputs</a>, if any.
   *
   * <p>This is present if and only if at least one extension output is present in the return value.
   *
   * @see <a
   *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-authenticator-extension-processing">§9.5.
   *     Authenticator Extension Processing</a>
   * @see AuthenticatorAssertionExtensionOutputs
   * @see #getClientExtensionOutputs()
   */
  @JsonIgnore
  public Optional<AuthenticatorAssertionExtensionOutputs> getAuthenticatorExtensionOutputs() {
    return AuthenticatorAssertionExtensionOutputs.fromAuthenticatorData(
        credentialResponse.getResponse().getParsedAuthenticatorData());
  }
}
