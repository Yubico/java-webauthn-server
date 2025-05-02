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
import com.yubico.webauthn.data.AuthenticatorAttachment;
import com.yubico.webauthn.data.AuthenticatorData;
import com.yubico.webauthn.data.AuthenticatorDataFlags;
import com.yubico.webauthn.data.AuthenticatorResponse;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.ClientAssertionExtensionOutputs;
import com.yubico.webauthn.data.PublicKeyCredential;
import java.util.Optional;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NonNull;
import lombok.Value;

/**
 * The result of a call to {@link RelyingPartyV2#finishAssertion(FinishAssertionOptions)}.
 *
 * @deprecated EXPERIMENTAL: This is an experimental feature. It is likely to change or be deleted
 *     before reaching a mature release.
 */
@Deprecated
@Value
public class AssertionResultV2<C extends CredentialRecord> {

  /** <code>true</code> if the assertion was verified successfully. */
  private final boolean success;

  @JsonProperty
  @Getter(AccessLevel.NONE)
  private final PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs>
      credentialResponse;

  /**
   * The {@link CredentialRecord} that was returned by {@link
   * CredentialRepositoryV2#lookup(ByteArray, ByteArray)} and whose public key was used to
   * successfully verify the assertion signature.
   *
   * <p>NOTE: The {@link CredentialRecord#getSignatureCount() signature count}, {@link
   * CredentialRecord#isBackupEligible() backup eligibility} and {@link
   * CredentialRecord#isBackedUp() backup state} properties in this object will reflect the state
   * <i>before</i> the assertion operation, not the new state. When updating your database state,
   * use the signature counter and backup state from {@link #getSignatureCount()}, {@link
   * #isBackupEligible()} and {@link #isBackedUp()} instead.
   *
   * @deprecated EXPERIMENTAL: This is an experimental feature. It is likely to change or be deleted
   *     before reaching a mature release.
   */
  @Deprecated private final C credential;

  /**
   * <code>true</code> if and only if at least one of the following is true:
   *
   * <ul>
   *   <li>The {@link AuthenticatorData#getSignatureCounter() signature counter value} in the
   *       assertion was strictly greater than {@link CredentialRecord#getSignatureCount() the
   *       stored one}.
   *   <li>The {@link AuthenticatorData#getSignatureCounter() signature counter value} in the
   *       assertion and {@link CredentialRecord#getSignatureCount() the stored one} were both zero.
   * </ul>
   *
   * @see <a
   *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-authenticator-data">§6.1.
   *     Authenticator Data</a>
   * @see AuthenticatorData#getSignatureCounter()
   * @see CredentialRecord#getSignatureCount()
   * @see RelyingParty.RelyingPartyBuilder#validateSignatureCounter(boolean)
   */
  private final boolean signatureCounterValid;

  @JsonCreator
  AssertionResultV2(
      @JsonProperty("success") boolean success,
      @NonNull @JsonProperty("credentialResponse")
          PublicKeyCredential<AuthenticatorAssertionResponse, ClientAssertionExtensionOutputs>
              credentialResponse,
      @NonNull @JsonProperty("credential") C credential,
      @JsonProperty("signatureCounterValid") boolean signatureCounterValid) {
    this.success = success;
    this.credentialResponse = credentialResponse;
    this.credential = credential;
    this.signatureCounterValid = signatureCounterValid;
  }

  /**
   * Check whether the <a href="https://www.w3.org/TR/webauthn/#user-verification">user
   * verification</a> as performed during the authentication ceremony.
   *
   * <p>This flag is also available via <code>
   * {@link PublicKeyCredential}.{@link PublicKeyCredential#getResponse() getResponse()}.{@link AuthenticatorResponse#getParsedAuthenticatorData() getParsedAuthenticatorData()}.{@link AuthenticatorData#getFlags() getFlags()}.{@link AuthenticatorDataFlags#UV UV}
   * </code>.
   *
   * @return <code>true</code> if and only if the authenticator claims to have performed user
   *     verification during the authentication ceremony.
   * @see <a href="https://www.w3.org/TR/webauthn/#user-verification">User Verification</a>
   * @see <a href="https://w3c.github.io/webauthn/#authdata-flags-uv">UV flag in §6.1. Authenticator
   *     Data</a>
   */
  @JsonIgnore
  public boolean isUserVerified() {
    return credentialResponse.getResponse().getParsedAuthenticatorData().getFlags().UV;
  }

  /**
   * Check whether the asserted credential is <a
   * href="https://w3c.github.io/webauthn/#backup-eligible">backup eligible</a>, using the <a
   * href="https://w3c.github.io/webauthn/#authdata-flags-be">BE flag</a> in the authenticator data.
   *
   * <p>You SHOULD store this value in your representation of the corresponding {@link
   * CredentialRecord} if no value is stored yet. {@link CredentialRepository} implementations
   * SHOULD set this value when reconstructing that {@link CredentialRecord}.
   *
   * @return <code>true</code> if and only if the created credential is backup eligible. NOTE that
   *     this is only a hint and not a guarantee, unless backed by a trusted authenticator
   *     attestation.
   * @see <a href="https://w3c.github.io/webauthn/#backup-eligible">Backup Eligible in §4.
   *     Terminology</a>
   * @see <a href="https://w3c.github.io/webauthn/#authdata-flags-be">BE flag in §6.1. Authenticator
   *     Data</a>
   * @deprecated EXPERIMENTAL: This feature is from a not yet mature standard; it could change as
   *     the standard matures.
   */
  @Deprecated
  @JsonIgnore
  public boolean isBackupEligible() {
    return credentialResponse.getResponse().getParsedAuthenticatorData().getFlags().BE;
  }

  /**
   * Get the current <a href="https://w3c.github.io/webauthn/#backup-state">backup state</a> of the
   * asserted credential, using the <a href="https://w3c.github.io/webauthn/#authdata-flags-bs">BS
   * flag</a> in the authenticator data.
   *
   * <p>You SHOULD update this value in your representation of a {@link CredentialRecord}. {@link
   * CredentialRepository} implementations SHOULD set this value when reconstructing that {@link
   * CredentialRecord}.
   *
   * @return <code>true</code> if and only if the created credential is believed to currently be
   *     backed up. NOTE that this is only a hint and not a guarantee, unless backed by a trusted
   *     authenticator attestation.
   * @see <a href="https://w3c.github.io/webauthn/#backup-state">Backup State in §4. Terminology</a>
   * @see <a href="https://w3c.github.io/webauthn/#authdata-flags-bs">BS flag in §6.1. Authenticator
   *     Data</a>
   * @deprecated EXPERIMENTAL: This feature is from a not yet mature standard; it could change as
   *     the standard matures.
   */
  @Deprecated
  @JsonIgnore
  public boolean isBackedUp() {
    return credentialResponse.getResponse().getParsedAuthenticatorData().getFlags().BS;
  }

  /**
   * The <a href="https://w3c.github.io/webauthn/#authenticator-attachment-modality">authenticator
   * attachment modality</a> in effect at the time the asserted credential was used.
   *
   * @see PublicKeyCredential#getAuthenticatorAttachment()
   * @deprecated EXPERIMENTAL: This feature is from a not yet mature standard; it could change as
   *     the standard matures.
   */
  @Deprecated
  @JsonIgnore
  public Optional<AuthenticatorAttachment> getAuthenticatorAttachment() {
    return credentialResponse.getAuthenticatorAttachment();
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
