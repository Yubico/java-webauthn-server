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

import com.yubico.webauthn.data.AssertionExtensionInputs;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions;
import com.yubico.webauthn.data.UserVerificationRequirement;
import java.util.Optional;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;

/** Parameters for {@link RelyingParty#startAssertion(StartAssertionOptions)}. */
@Value
@Builder(toBuilder = true)
public class StartAssertionOptions {

  private final String username;

  private final ByteArray userHandle;

  /**
   * Extension inputs for this authentication operation.
   *
   * <p>If {@link RelyingParty#getAppId()} is set, {@link
   * RelyingParty#startAssertion(StartAssertionOptions)} will overwrite any {@link
   * AssertionExtensionInputs#getAppid() appId} extension input set herein.
   *
   * <p>The default specifies no extension inputs.
   */
  @NonNull @Builder.Default
  private final AssertionExtensionInputs extensions = AssertionExtensionInputs.builder().build();

  /**
   * The value for {@link PublicKeyCredentialRequestOptions#getUserVerification()} for this
   * authentication operation.
   *
   * <p>If set to {@link UserVerificationRequirement#REQUIRED}, then {@link
   * RelyingParty#finishAssertion(FinishAssertionOptions)} will enforce that <a
   * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408#user-verification">user
   * verification</a>was performed in this authentication ceremony.
   *
   * <p>The default is {@link UserVerificationRequirement#PREFERRED}.
   */
  private final UserVerificationRequirement userVerification;

  /**
   * The value for {@link PublicKeyCredentialRequestOptions#getTimeout()} for this authentication
   * operation.
   *
   * <p>This library does not take the timeout into account in any way, other than passing it
   * through to the {@link PublicKeyCredentialRequestOptions} so it can be used as an argument to
   * <code>navigator.credentials.get()</code> on the client side.
   *
   * <p>The default is empty.
   */
  private final Long timeout;

  /**
   * The username of the user to authenticate, if the user has already been identified.
   *
   * <p>Mutually exclusive with {@link #getUserHandle()}.
   *
   * <p>If this or {@link #getUserHandle()} is present, then {@link
   * RelyingParty#startAssertion(StartAssertionOptions)} will set {@link
   * PublicKeyCredentialRequestOptions#getAllowCredentials()} to the list of that user's
   * credentials.
   *
   * <p>If this and {@link #getUserHandle()} are both absent, that implies a first-factor
   * authentication operation - meaning identification of the user is deferred until after receiving
   * the response from the client.
   *
   * <p>The default is empty (absent).
   *
   * @see <a
   *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#client-side-discoverable-public-key-credential-source">Client-side-resident
   *     credential</a>
   */
  public Optional<String> getUsername() {
    return Optional.ofNullable(username);
  }

  /**
   * The user handle of the user to authenticate, if the user has already been identified.
   *
   * <p>Mutually exclusive with {@link #getUsername()}.
   *
   * <p>If this or {@link #getUsername()} is present, then {@link
   * RelyingParty#startAssertion(StartAssertionOptions)} will set {@link
   * PublicKeyCredentialRequestOptions#getAllowCredentials()} to the list of that user's
   * credentials.
   *
   * <p>If this and {@link #getUsername()} are both absent, that implies a first-factor
   * authentication operation - meaning identification of the user is deferred until after receiving
   * the response from the client.
   *
   * <p>The default is empty (absent).
   *
   * @see #getUsername()
   * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#user-handle">User Handle</a>
   * @see <a
   *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#client-side-discoverable-public-key-credential-source">Client-side-resident
   *     credential</a>
   */
  public Optional<ByteArray> getUserHandle() {
    return Optional.ofNullable(userHandle);
  }

  /**
   * The value for {@link PublicKeyCredentialRequestOptions#getUserVerification()} for this
   * authentication operation.
   *
   * <p>If set to {@link UserVerificationRequirement#REQUIRED}, then {@link
   * RelyingParty#finishAssertion(FinishAssertionOptions)} will enforce that <a
   * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408#user-verification">user
   * verification</a>was performed in this authentication ceremony.
   *
   * <p>The default is {@link UserVerificationRequirement#PREFERRED}.
   */
  public Optional<UserVerificationRequirement> getUserVerification() {
    return Optional.ofNullable(userVerification);
  }

  /**
   * The value for {@link PublicKeyCredentialRequestOptions#getTimeout()} for this authentication
   * operation.
   *
   * <p>This library does not take the timeout into account in any way, other than passing it
   * through to the {@link PublicKeyCredentialRequestOptions} so it can be used as an argument to
   * <code>navigator.credentials.get()</code> on the client side.
   *
   * <p>The default is empty.
   */
  public Optional<Long> getTimeout() {
    return Optional.ofNullable(timeout);
  }

  public static class StartAssertionOptionsBuilder {
    private String username = null;
    private ByteArray userHandle = null;
    private UserVerificationRequirement userVerification = null;
    private Long timeout = null;

    /**
     * The username of the user to authenticate, if the user has already been identified.
     *
     * <p>Mutually exclusive with {@link #userHandle(Optional)}. Setting this to a present value
     * will set {@link #userHandle(Optional)} to empty.
     *
     * <p>If this or {@link #userHandle(Optional)} is present, then {@link
     * RelyingParty#startAssertion(StartAssertionOptions)} will set {@link
     * PublicKeyCredentialRequestOptions#getAllowCredentials()} to the list of that user's
     * credentials.
     *
     * <p>If this and {@link #getUserHandle()} are both absent, that implies a first-factor
     * authentication operation - meaning identification of the user is deferred until after
     * receiving the response from the client.
     *
     * <p>The default is empty (absent).
     *
     * @see #username(String)
     * @see #userHandle(Optional)
     * @see #userHandle(ByteArray)
     * @see <a
     *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#client-side-discoverable-public-key-credential-source">Client-side-resident
     *     credential</a>
     */
    public StartAssertionOptionsBuilder username(@NonNull Optional<String> username) {
      this.username = username.orElse(null);
      if (username.isPresent()) {
        this.userHandle = null;
      }
      return this;
    }

    /**
     * The username of the user to authenticate, if the user has already been identified.
     *
     * <p>Mutually exclusive with {@link #userHandle(Optional)}. Setting this to a non-null value
     * will set {@link #userHandle(Optional)} to empty.
     *
     * <p>If this or {@link #userHandle(Optional)} is present, then {@link
     * RelyingParty#startAssertion(StartAssertionOptions)} will set {@link
     * PublicKeyCredentialRequestOptions#getAllowCredentials()} to the list of that user's
     * credentials.
     *
     * <p>If this and {@link #getUserHandle()} are both absent, that implies a first-factor
     * authentication operation - meaning identification of the user is deferred until after
     * receiving the response from the client.
     *
     * <p>The default is empty (absent).
     *
     * @see #username(Optional)
     * @see #userHandle(Optional)
     * @see #userHandle(ByteArray)
     * @see <a
     *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#client-side-discoverable-public-key-credential-source">Client-side-resident
     *     credential</a>
     */
    public StartAssertionOptionsBuilder username(String username) {
      return this.username(Optional.ofNullable(username));
    }

    /**
     * The user handle of the user to authenticate, if the user has already been identified.
     *
     * <p>Mutually exclusive with {@link #username(Optional)}. Setting this to a present value will
     * set {@link #username(Optional)} to empty.
     *
     * <p>If this or {@link #username(Optional)} is present, then {@link
     * RelyingParty#startAssertion(StartAssertionOptions)} will set {@link
     * PublicKeyCredentialRequestOptions#getAllowCredentials()} to the list of that user's
     * credentials.
     *
     * <p>If this and {@link #getUsername()} are both absent, that implies a first-factor
     * authentication operation - meaning identification of the user is deferred until after
     * receiving the response from the client.
     *
     * <p>The default is empty (absent).
     *
     * @see #username(String)
     * @see #username(Optional)
     * @see #userHandle(ByteArray)
     * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#user-handle">User
     *     Handle</a>
     * @see <a
     *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#client-side-discoverable-public-key-credential-source">Client-side-resident
     *     credential</a>
     */
    public StartAssertionOptionsBuilder userHandle(@NonNull Optional<ByteArray> userHandle) {
      this.userHandle = userHandle.orElse(null);
      if (userHandle.isPresent()) {
        this.username = null;
      }
      return this;
    }

    /**
     * The user handle of the user to authenticate, if the user has already been identified.
     *
     * <p>Mutually exclusive with {@link #username(Optional)}. Setting this to a non-null value will
     * set {@link #username(Optional)} to empty.
     *
     * <p>If this or {@link #username(Optional)} is present, then {@link
     * RelyingParty#startAssertion(StartAssertionOptions)} will set {@link
     * PublicKeyCredentialRequestOptions#getAllowCredentials()} to the list of that user's
     * credentials.
     *
     * <p>If this and {@link #getUsername()} are both absent, that implies a first-factor
     * authentication operation - meaning identification of the user is deferred until after
     * receiving the response from the client.
     *
     * <p>The default is empty (absent).
     *
     * @see #username(String)
     * @see #username(Optional)
     * @see #userHandle(Optional)
     * @see <a
     *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#client-side-discoverable-public-key-credential-source">Client-side-resident
     *     credential</a>
     */
    public StartAssertionOptionsBuilder userHandle(ByteArray userHandle) {
      return this.userHandle(Optional.ofNullable(userHandle));
    }

    /**
     * The value for {@link PublicKeyCredentialRequestOptions#getUserVerification()} for this
     * authentication operation.
     *
     * <p>If set to {@link UserVerificationRequirement#REQUIRED}, then {@link
     * RelyingParty#finishAssertion(FinishAssertionOptions)} will enforce that <a
     * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#user-verification">user
     * verification</a>was performed in this authentication ceremony.
     *
     * <p>The default is {@link UserVerificationRequirement#PREFERRED}.
     */
    public StartAssertionOptionsBuilder userVerification(
        @NonNull Optional<UserVerificationRequirement> userVerification) {
      this.userVerification = userVerification.orElse(null);
      return this;
    }

    /**
     * The value for {@link PublicKeyCredentialRequestOptions#getUserVerification()} for this
     * authentication operation.
     *
     * <p>If set to {@link UserVerificationRequirement#REQUIRED}, then {@link
     * RelyingParty#finishAssertion(FinishAssertionOptions)} will enforce that <a
     * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#user-verification">user
     * verification</a>was performed in this authentication ceremony.
     *
     * <p>The default is {@link UserVerificationRequirement#PREFERRED}.
     */
    public StartAssertionOptionsBuilder userVerification(
        UserVerificationRequirement userVerification) {
      return this.userVerification(Optional.ofNullable(userVerification));
    }

    /**
     * The value for {@link PublicKeyCredentialRequestOptions#getTimeout()} for this authentication
     * operation.
     *
     * <p>This library does not take the timeout into account in any way, other than passing it
     * through to the {@link PublicKeyCredentialRequestOptions} so it can be used as an argument to
     * <code>navigator.credentials.get()</code> on the client side.
     *
     * <p>The default is empty.
     */
    public StartAssertionOptionsBuilder timeout(@NonNull Optional<Long> timeout) {
      if (timeout.isPresent() && timeout.get() <= 0) {
        throw new IllegalArgumentException("timeout must be positive, was: " + timeout.get());
      }
      this.timeout = timeout.orElse(null);
      return this;
    }

    /**
     * The value for {@link PublicKeyCredentialRequestOptions#getTimeout()} for this authentication
     * operation.
     *
     * <p>This library does not take the timeout into account in any way, other than passing it
     * through to the {@link PublicKeyCredentialRequestOptions} so it can be used as an argument to
     * <code>navigator.credentials.get()</code> on the client side.
     *
     * <p>The default is empty.
     */
    public StartAssertionOptionsBuilder timeout(long timeout) {
      return this.timeout(Optional.of(timeout));
    }

    /*
     * Workaround, see: https://github.com/rzwitserloot/lombok/issues/2623#issuecomment-714816001
     * Consider reverting this workaround if Lombok fixes that issue.
     */
    private StartAssertionOptionsBuilder timeout(Long timeout) {
      return this.timeout(Optional.ofNullable(timeout));
    }
  }
}
