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
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions;
import com.yubico.webauthn.data.UserVerificationRequirement;
import java.util.Optional;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;

/**
 * Parameters for {@link RelyingParty#startAssertion(StartAssertionOptions)}.
 */
@Value
@Builder(toBuilder = true)
public class StartAssertionOptions {

    /**
     * The username of the user to authenticate, if the user has already been identified.
     * <p>
     * If this is absent, that implies a first-factor authentication operation - meaning identification of the user is
     * deferred until after receiving the response from the client.
     * </p>
     *
     * <p>
     * The default is empty (absent).
     * </p>
     *
     * @see <a href="https://www.w3.org/TR/2019/PR-webauthn-20190117/#client-side-resident-public-key-credential-source">Client-side-resident
     * credential</a>
     */
    @NonNull
    private final Optional<String> username;

    /**
     * Extension inputs for this authentication operation.
     * <p>
     * If {@link RelyingParty#getAppId()} is set, {@link RelyingParty#startAssertion(StartAssertionOptions)} will
     * overwrite any {@link AssertionExtensionInputs#getAppid() appId} extension input set herein.
     * </p>
     *
     * <p>
     * The default specifies no extension inputs.
     * </p>
     */
    @NonNull
    @Builder.Default
    private final AssertionExtensionInputs extensions = AssertionExtensionInputs.builder().build();

    /**
     * The value for {@link PublicKeyCredentialRequestOptions#getUserVerification()} for this authentication operation.
     * <p>
     * The default is {@link UserVerificationRequirement#PREFERRED}.
     * </p>
     */
    @NonNull
    private final Optional<UserVerificationRequirement> userVerification;

    /**
     * The value for {@link PublicKeyCredentialRequestOptions#getTimeout()} for this authentication operation.
     * <p>
     * This library does not take the timeout into account in any way, other than passing it through to the {@link
     * PublicKeyCredentialRequestOptions} so it can be used as an argument to
     * <code>navigator.credentials.get()</code> on the client side.
     * </p>
     * <p>
     * The default is empty.
     * </p>
     */
    @NonNull
    private final Optional<Long> timeout;

    public static class StartAssertionOptionsBuilder {
        private @NonNull Optional<String> username = Optional.empty();
        private @NonNull Optional<UserVerificationRequirement> userVerification = Optional.empty();
        private @NonNull Optional<Long> timeout = Optional.empty();

        /**
         * The username of the user to authenticate, if the user has already been identified.
         * <p>
         * If this is absent, that implies a first-factor authentication operation - meaning identification of the user is
         * deferred until after receiving the response from the client.
         * </p>
         *
         * <p>
         * The default is empty (absent).
         * </p>
         *
         * @see <a href="https://www.w3.org/TR/2019/PR-webauthn-20190117/#client-side-resident-public-key-credential-source">Client-side-resident
         * credential</a>
         */
        public StartAssertionOptionsBuilder username(@NonNull Optional<String> username) {
            this.username = username;
            return this;
        }

        /**
         * The username of the user to authenticate, if the user has already been identified.
         * <p>
         * If this is absent, that implies a first-factor authentication operation - meaning identification of the user is
         * deferred until after receiving the response from the client.
         * </p>
         *
         * <p>
         * The default is empty (absent).
         * </p>
         *
         * @see <a href="https://www.w3.org/TR/2019/PR-webauthn-20190117/#client-side-resident-public-key-credential-source">Client-side-resident
         * credential</a>
         */
        public StartAssertionOptionsBuilder username(@NonNull String username) {
            return this.username(Optional.of(username));
        }

        /**
         * The value for {@link PublicKeyCredentialRequestOptions#getUserVerification()} for this authentication operation.
         * <p>
         * The default is {@link UserVerificationRequirement#PREFERRED}.
         * </p>
         */
        public StartAssertionOptionsBuilder userVerification(@NonNull Optional<UserVerificationRequirement> userVerification) {
            this.userVerification = userVerification;
            return this;
        }

        /**
         * The value for {@link PublicKeyCredentialRequestOptions#getUserVerification()} for this authentication operation.
         * <p>
         * The default is {@link UserVerificationRequirement#PREFERRED}.
         * </p>
         */
        public StartAssertionOptionsBuilder userVerification(@NonNull UserVerificationRequirement userVerification) {
            return this.userVerification(Optional.of(userVerification));
        }

        /**
         * The value for {@link PublicKeyCredentialRequestOptions#getTimeout()} for this authentication operation.
         * <p>
         * This library does not take the timeout into account in any way, other than passing it through to the {@link
         * PublicKeyCredentialRequestOptions} so it can be used as an argument to
         * <code>navigator.credentials.get()</code> on the client side.
         * </p>
         * <p>
         * The default is empty.
         * </p>
         */
        public StartAssertionOptionsBuilder timeout(@NonNull Optional<Long> timeout) {
            if (timeout.isPresent() && timeout.get() <= 0) {
                throw new IllegalArgumentException("timeout must be positive, was: " + timeout.get());
            }
            this.timeout = timeout;
            return this;
        }

        /**
         * The value for {@link PublicKeyCredentialRequestOptions#getTimeout()} for this authentication operation.
         * <p>
         * This library does not take the timeout into account in any way, other than passing it through to the {@link
         * PublicKeyCredentialRequestOptions} so it can be used as an argument to
         * <code>navigator.credentials.get()</code> on the client side.
         * </p>
         * <p>
         * The default is empty.
         * </p>
         */
        public StartAssertionOptionsBuilder timeout(long timeout) {
            return this.timeout(Optional.of(timeout));
        }
    }
}
