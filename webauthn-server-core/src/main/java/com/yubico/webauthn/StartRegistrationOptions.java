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

import com.yubico.webauthn.data.AuthenticatorSelectionCriteria;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.data.PublicKeyCredentialHint;
import com.yubico.webauthn.data.RegistrationExtensionInputs;
import com.yubico.webauthn.data.UserIdentity;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;

/** Parameters for {@link RelyingParty#startRegistration(StartRegistrationOptions)}. */
@Value
@Builder(toBuilder = true)
public class StartRegistrationOptions {

  /** Identifiers for the user creating a credential. */
  @NonNull private final UserIdentity user;

  /**
   * Constraints on what kind of authenticator the user is allowed to use to create the credential,
   * and on features that authenticator must or should support.
   */
  private final AuthenticatorSelectionCriteria authenticatorSelection;

  /** Extension inputs for this registration operation. */
  @NonNull @Builder.Default
  private final RegistrationExtensionInputs extensions =
      RegistrationExtensionInputs.builder().build();

  /**
   * The value for {@link PublicKeyCredentialCreationOptions#getTimeout()} for this registration
   * operation.
   *
   * <p>This library does not take the timeout into account in any way, other than passing it
   * through to the {@link PublicKeyCredentialCreationOptions} so it can be used as an argument to
   * <code>navigator.credentials.create()</code> on the client side.
   *
   * <p>The default is empty.
   */
  private final Long timeout;

  /**
   * Zero or more hints, in descending order of preference, to guide the user agent in interacting
   * with the user during this registration operation.
   *
   * <p>For example, the {@link PublicKeyCredentialHint#SECURITY_KEY} hint may be used to ask the
   * client to emphasize the option of registering with an external security key, or the {@link
   * PublicKeyCredentialHint#CLIENT_DEVICE} hint may be used to ask the client to emphasize the
   * option of registering a built-in passkey provider.
   *
   * <p>These hints are not requirements, and do not bind the user-agent, but may guide it in
   * providing the best experience by using contextual information about the request.
   *
   * <p>Hints MAY contradict preferences in {@link #getAuthenticatorSelection()}. When this occurs,
   * the hints take precedence.
   *
   * <p>This library does not take these hints into account in any way, other than passing them
   * through to the {@link PublicKeyCredentialCreationOptions} so they can be used in the argument
   * to <code>navigator.credentials.create()</code> on the client side.
   *
   * <p>The default is empty.
   *
   * @see PublicKeyCredentialHint
   * @see StartRegistrationOptionsBuilder#hints(List)
   * @see StartRegistrationOptionsBuilder#hints(String...)
   * @see StartRegistrationOptionsBuilder#hints(PublicKeyCredentialHint...)
   * @see <a
   *     href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialcreationoptions-hints">PublicKeyCredentialCreationOptions.hints</a>
   * @see <a
   *     href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#enumdef-publickeycredentialhints">§5.8.7.
   *     User-agent Hints Enumeration (enum PublicKeyCredentialHints)</a>
   */
  private final List<String> hints;

  private StartRegistrationOptions(
      @NonNull UserIdentity user,
      AuthenticatorSelectionCriteria authenticatorSelection,
      @NonNull RegistrationExtensionInputs extensions,
      Long timeout,
      List<String> hints) {
    this.user = user;
    this.authenticatorSelection = authenticatorSelection;
    this.extensions = extensions;
    this.timeout = timeout;
    this.hints = hints == null ? Collections.emptyList() : Collections.unmodifiableList(hints);
  }

  /**
   * Constraints on what kind of authenticator the user is allowed to use to create the credential,
   * and on features that authenticator must or should support.
   */
  public Optional<AuthenticatorSelectionCriteria> getAuthenticatorSelection() {
    return Optional.ofNullable(authenticatorSelection);
  }

  /**
   * The value for {@link PublicKeyCredentialCreationOptions#getTimeout()} for this registration
   * operation.
   *
   * <p>This library does not take the timeout into account in any way, other than passing it
   * through to the {@link PublicKeyCredentialCreationOptions} so it can be used as an argument to
   * <code>navigator.credentials.create()</code> on the client side.
   *
   * <p>The default is empty.
   */
  public Optional<Long> getTimeout() {
    return Optional.ofNullable(timeout);
  }

  public static StartRegistrationOptionsBuilder.MandatoryStages builder() {
    return new StartRegistrationOptionsBuilder.MandatoryStages();
  }

  public static class StartRegistrationOptionsBuilder {
    private AuthenticatorSelectionCriteria authenticatorSelection = null;
    private Long timeout = null;

    public static class MandatoryStages {
      private final StartRegistrationOptionsBuilder builder = new StartRegistrationOptionsBuilder();

      /**
       * {@link StartRegistrationOptionsBuilder#user(UserIdentity) user} is a required parameter.
       *
       * @see StartRegistrationOptionsBuilder#user(UserIdentity)
       */
      public StartRegistrationOptionsBuilder user(UserIdentity user) {
        return builder.user(user);
      }
    }

    /**
     * Constraints on what kind of authenticator the user is allowed to use to create the
     * credential, and on features that authenticator must or should support.
     */
    public StartRegistrationOptionsBuilder authenticatorSelection(
        @NonNull Optional<AuthenticatorSelectionCriteria> authenticatorSelection) {
      return this.authenticatorSelection(authenticatorSelection.orElse(null));
    }

    /**
     * Constraints on what kind of authenticator the user is allowed to use to create the
     * credential, and on features that authenticator must or should support.
     */
    public StartRegistrationOptionsBuilder authenticatorSelection(
        AuthenticatorSelectionCriteria authenticatorSelection) {
      this.authenticatorSelection = authenticatorSelection;
      return this;
    }

    /**
     * The value for {@link PublicKeyCredentialCreationOptions#getTimeout()} for this registration
     * operation.
     *
     * <p>This library does not take the timeout into account in any way, other than passing it
     * through to the {@link PublicKeyCredentialCreationOptions} so it can be used as an argument to
     * <code>navigator.credentials.create()</code> on the client side.
     *
     * <p>The default is empty.
     */
    public StartRegistrationOptionsBuilder timeout(@NonNull Optional<Long> timeout) {
      if (timeout.isPresent() && timeout.get() <= 0) {
        throw new IllegalArgumentException("timeout must be positive, was: " + timeout.get());
      }
      this.timeout = timeout.orElse(null);
      return this;
    }

    /**
     * The value for {@link PublicKeyCredentialCreationOptions#getTimeout()} for this registration
     * operation.
     *
     * <p>This library does not take the timeout into account in any way, other than passing it
     * through to the {@link PublicKeyCredentialCreationOptions} so it can be used as an argument to
     * <code>navigator.credentials.create()</code> on the client side.
     *
     * <p>The default is empty.
     */
    public StartRegistrationOptionsBuilder timeout(long timeout) {
      return this.timeout(Optional.of(timeout));
    }

    /**
     * Zero or more hints, in descending order of preference, to guide the user agent in interacting
     * with the user during this registration operation.
     *
     * <p>Setting this property multiple times overwrites any value set previously.
     *
     * <p>For example, the {@link PublicKeyCredentialHint#SECURITY_KEY} hint may be used to ask the
     * client to emphasize the option of registering with an external security key, or the {@link
     * PublicKeyCredentialHint#CLIENT_DEVICE} hint may be used to ask the client to emphasize the
     * option of registering a built-in passkey provider.
     *
     * <p>These hints are not requirements, and do not bind the user-agent, but may guide it in
     * providing the best experience by using contextual information about the request.
     *
     * <p>Hints MAY contradict preferences in {@link #getAuthenticatorSelection()}. When this
     * occurs, the hints take precedence.
     *
     * <p>This library does not take these hints into account in any way, other than passing them
     * through to the {@link PublicKeyCredentialCreationOptions} so they can be used in the argument
     * to <code>navigator.credentials.create()</code> on the client side.
     *
     * <p>The default is empty.
     *
     * @see PublicKeyCredentialHint
     * @see StartRegistrationOptions#getHints()
     * @see StartRegistrationOptionsBuilder#hints(List)
     * @see StartRegistrationOptionsBuilder#hints(PublicKeyCredentialHint...)
     * @see <a
     *     href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialcreationoptions-hints">PublicKeyCredentialCreationOptions.hints</a>
     * @see <a
     *     href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#enumdef-publickeycredentialhints">§5.8.7.
     *     User-agent Hints Enumeration (enum PublicKeyCredentialHints)</a>
     */
    public StartRegistrationOptionsBuilder hints(@NonNull String... hints) {
      this.hints = Arrays.asList(hints);
      return this;
    }

    /**
     * Zero or more hints, in descending order of preference, to guide the user agent in interacting
     * with the user during this registration operation.
     *
     * <p>Setting this property multiple times overwrites any value set previously.
     *
     * <p>For example, the {@link PublicKeyCredentialHint#SECURITY_KEY} hint may be used to ask the
     * client to emphasize the option of registering with an external security key, or the {@link
     * PublicKeyCredentialHint#CLIENT_DEVICE} hint may be used to ask the client to emphasize the
     * option of registering a built-in passkey provider.
     *
     * <p>These hints are not requirements, and do not bind the user-agent, but may guide it in
     * providing the best experience by using contextual information about the request.
     *
     * <p>Hints MAY contradict preferences in {@link #getAuthenticatorSelection()}. When this
     * occurs, the hints take precedence.
     *
     * <p>This library does not take these hints into account in any way, other than passing them
     * through to the {@link PublicKeyCredentialCreationOptions} so they can be used in the argument
     * to <code>navigator.credentials.create()</code> on the client side.
     *
     * <p>The default is empty.
     *
     * @see PublicKeyCredentialHint
     * @see StartRegistrationOptions#getHints()
     * @see StartRegistrationOptionsBuilder#hints(List)
     * @see StartRegistrationOptionsBuilder#hints(String...)
     * @see <a
     *     href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialcreationoptions-hints">PublicKeyCredentialCreationOptions.hints</a>
     * @see <a
     *     href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#enumdef-publickeycredentialhints">§5.8.7.
     *     User-agent Hints Enumeration (enum PublicKeyCredentialHints)</a>
     */
    public StartRegistrationOptionsBuilder hints(@NonNull PublicKeyCredentialHint... hints) {
      return this.hints(
          Arrays.stream(hints).map(PublicKeyCredentialHint::getValue).toArray(String[]::new));
    }

    /**
     * Zero or more hints, in descending order of preference, to guide the user agent in interacting
     * with the user during this registration operation.
     *
     * <p>Setting this property multiple times overwrites any value set previously.
     *
     * <p>For example, the {@link PublicKeyCredentialHint#SECURITY_KEY} hint may be used to ask the
     * client to emphasize the option of registering with an external security key, or the {@link
     * PublicKeyCredentialHint#CLIENT_DEVICE} hint may be used to ask the client to emphasize the
     * option of registering a built-in passkey provider.
     *
     * <p>These hints are not requirements, and do not bind the user-agent, but may guide it in
     * providing the best experience by using contextual information about the request.
     *
     * <p>Hints MAY contradict preferences in {@link #getAuthenticatorSelection()}. When this
     * occurs, the hints take precedence.
     *
     * <p>This library does not take these hints into account in any way, other than passing them
     * through to the {@link PublicKeyCredentialCreationOptions} so they can be used in the argument
     * to <code>navigator.credentials.create()</code> on the client side.
     *
     * <p>The default is empty.
     *
     * @see PublicKeyCredentialHint
     * @see StartRegistrationOptions#getHints()
     * @see StartRegistrationOptionsBuilder#hints(String...)
     * @see StartRegistrationOptionsBuilder#hints(PublicKeyCredentialHint...)
     * @see <a
     *     href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#dom-publickeycredentialcreationoptions-hints">PublicKeyCredentialCreationOptions.hints</a>
     * @see <a
     *     href="https://www.w3.org/TR/2023/WD-webauthn-3-20230927/#enumdef-publickeycredentialhints">§5.8.7.
     *     User-agent Hints Enumeration (enum PublicKeyCredentialHints)</a>
     */
    public StartRegistrationOptionsBuilder hints(@NonNull List<String> hints) {
      this.hints = hints;
      return this;
    }
  }
}
