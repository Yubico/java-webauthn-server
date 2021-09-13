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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Optional;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;

/**
 * This class may be used to specify requirements regarding authenticator attributes.
 *
 * @see <a
 *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#dictdef-authenticatorselectioncriteria">§5.4.4.
 *     Authenticator Selection Criteria (dictionary AuthenticatorSelectionCriteria) </a>
 */
@Value
@Builder(toBuilder = true)
public class AuthenticatorSelectionCriteria {

  /**
   * If present, eligible authenticators are filtered to only authenticators attached with the
   * specified <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#enum-attachment">§5.4.5
   * Authenticator Attachment Enumeration (enum AuthenticatorAttachment)</a>.
   */
  private final AuthenticatorAttachment authenticatorAttachment;

  /**
   * Specifies the extent to which the Relying Party desires to create a client-side discoverable
   * credential. For historical reasons the naming retains the deprecated “resident” terminology.
   *
   * <p>The default is {@link ResidentKeyRequirement#DISCOURAGED}.
   *
   * @see ResidentKeyRequirement
   * @see <a
   *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#enum-residentKeyRequirement">§5.4.6.
   *     Resident Key Requirement Enumeration (enum ResidentKeyRequirement)</a>
   * @see <a
   *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#client-side-discoverable-credential">Client-side
   *     discoverable Credential</a>
   */
  private final ResidentKeyRequirement residentKey;

  /**
   * Describes the Relying Party's requirements regarding <a
   * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#user-verification">user
   * verification</a> for the <code>navigator.credentials.create()</code> operation. Eligible
   * authenticators are filtered to only those capable of satisfying this requirement.
   */
  private UserVerificationRequirement userVerification;

  /**
   * If present, eligible authenticators are filtered to only authenticators attached with the
   * specified <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#enum-attachment">§5.4.5
   * Authenticator Attachment Enumeration (enum AuthenticatorAttachment)</a>.
   */
  public Optional<AuthenticatorAttachment> getAuthenticatorAttachment() {
    return Optional.ofNullable(authenticatorAttachment);
  }

  /**
   * This member is retained for backwards compatibility with WebAuthn Level 1 and, for historical
   * reasons, its naming retains the deprecated “resident” terminology for discoverable credentials.
   *
   * @return <code>true</code> if and only if {@link #getResidentKey()} is {@link
   *     ResidentKeyRequirement#REQUIRED}.
   * @see #getResidentKey()
   * @deprecated Use {@link #getResidentKey()} instead.
   */
  @Deprecated
  public boolean isRequireResidentKey() {
    return residentKey == ResidentKeyRequirement.REQUIRED;
  }

  @JsonCreator
  private AuthenticatorSelectionCriteria(
      @JsonProperty("authenticatorAttachment") AuthenticatorAttachment authenticatorAttachment,
      @JsonProperty("requireResidentKey") Boolean requireResidentKey,
      @JsonProperty("residentKey") ResidentKeyRequirement residentKey,
      @JsonProperty("userVerification") UserVerificationRequirement userVerification) {
    this.authenticatorAttachment = authenticatorAttachment;

    if (residentKey == null && requireResidentKey != null) {
      this.residentKey =
          requireResidentKey ? ResidentKeyRequirement.REQUIRED : ResidentKeyRequirement.DISCOURAGED;
    } else {
      this.residentKey = residentKey == null ? ResidentKeyRequirement.DISCOURAGED : residentKey;
    }

    this.userVerification =
        userVerification == null ? UserVerificationRequirement.PREFERRED : userVerification;
  }

  /** For use by the builder. */
  private AuthenticatorSelectionCriteria(
      AuthenticatorAttachment authenticatorAttachment,
      ResidentKeyRequirement residentKey,
      UserVerificationRequirement userVerification) {
    this(authenticatorAttachment, null, residentKey, userVerification);
  }

  public static class AuthenticatorSelectionCriteriaBuilder {
    private AuthenticatorAttachment authenticatorAttachment = null;

    /**
     * If present, eligible authenticators are filtered to only authenticators attached with the
     * specified <a
     * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#enum-attachment">§5.4.5
     * Authenticator Attachment Enumeration (enum AuthenticatorAttachment)</a>.
     */
    public AuthenticatorSelectionCriteriaBuilder authenticatorAttachment(
        @NonNull Optional<AuthenticatorAttachment> authenticatorAttachment) {
      return this.authenticatorAttachment(authenticatorAttachment.orElse(null));
    }

    /**
     * If present, eligible authenticators are filtered to only authenticators attached with the
     * specified <a
     * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#enum-attachment">§5.4.5
     * Authenticator Attachment Enumeration (enum AuthenticatorAttachment)</a>.
     */
    public AuthenticatorSelectionCriteriaBuilder authenticatorAttachment(
        AuthenticatorAttachment authenticatorAttachment) {
      this.authenticatorAttachment = authenticatorAttachment;
      return this;
    }

    /**
     * This member is retained for backwards compatibility with WebAuthn Level 1 and, for historical
     * reasons, its naming retains the deprecated “resident” terminology for discoverable
     * credentials.
     *
     * <p><code>requireResidentKey(true)</code> is an alias of <code>residentKey(REQUIRED)
     * </code>.
     *
     * <p><code>requireResidentKey(false)</code> is an alias of <code>residentKey(DISCOURAGED)
     * </code>.
     *
     * @deprecated Use {@link #residentKey(ResidentKeyRequirement) residentKey} instead.
     * @see #residentKey(ResidentKeyRequirement)
     */
    @Deprecated
    public AuthenticatorSelectionCriteriaBuilder requireResidentKey(boolean requireResidentKey) {
      return residentKey(
          requireResidentKey
              ? ResidentKeyRequirement.REQUIRED
              : ResidentKeyRequirement.DISCOURAGED);
    }
  }
}
