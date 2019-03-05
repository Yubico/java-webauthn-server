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
import com.fasterxml.jackson.annotation.JsonProperty;
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions;
import java.util.Optional;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;


/**
 * A combination of a {@link PublicKeyCredentialRequestOptions} and, optionally, a {@link #getUsername() username}.
 */
@Value
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder(toBuilder = true)
public class AssertionRequest {

    /**
     * An object that can be serialized to JSON and passed as the <code>publicKey</code> argument to
     * <code>navigator.credentials.get()</code>.
     */
    @NonNull
    private final PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions;

    /**
     * The username of the user to authenticate, if the user has already been identified.
     * <p>
     * If this is absent, this indicates that this is a request for an assertion by a <a
     * href="https://www.w3.org/TR/2019/PR-webauthn-20190117/#client-side-resident-public-key-credential-source">client-side-resident
     * credential</a>, and identification of the user has been deferred until the response is received.
     * </p>
     */
    @NonNull
    private final Optional<String> username;

    @JsonCreator
    private AssertionRequest(
        @NonNull @JsonProperty("publicKeyCredentialRequestOptions") PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions,
        @JsonProperty("username") String username
    ) {
        this(publicKeyCredentialRequestOptions, Optional.ofNullable(username));
    }

    public static AssertionRequestBuilder.MandatoryStages builder() {
        return new AssertionRequestBuilder.MandatoryStages();
    }

    public static class AssertionRequestBuilder {
        private Optional<String> username = Optional.empty();

        public static class MandatoryStages {
            private final AssertionRequestBuilder builder = new AssertionRequestBuilder();

            /**
             * {@link AssertionRequestBuilder#publicKeyCredentialRequestOptions(PublicKeyCredentialRequestOptions)
             * publicKeyCredentialRequestOptions} is a required parameter.
             */
            public AssertionRequestBuilder publicKeyCredentialRequestOptions(PublicKeyCredentialRequestOptions publicKeyCredentialRequestOptions) {
                return builder.publicKeyCredentialRequestOptions(publicKeyCredentialRequestOptions);
            }
        }

        /**
         * The username of the user to authenticate, if the user has already been identified.
         * <p>
         * If this is absent, this indicates that this is a request for an assertion by a <a
         * href="https://www.w3.org/TR/2019/PR-webauthn-20190117/#client-side-resident-public-key-credential-source">client-side-resident
         * credential</a>, and identification of the user has been deferred until the response is received.
         * </p>
         */
        public AssertionRequestBuilder username(@NonNull Optional<String> username) {
            this.username = username;
            return this;
        }

        /**
         * The username of the user to authenticate, if the user has already been identified.
         * <p>
         * If this is absent, this indicates that this is a request for an assertion by a <a
         * href="https://www.w3.org/TR/2019/PR-webauthn-20190117/#client-side-resident-public-key-credential-source">client-side-resident
         * credential</a>, and identification of the user has been deferred until the response is received.
         * </p>
         */
        public AssertionRequestBuilder username(@NonNull String username) {
            return this.username(Optional.of(username));
        }
    }

}
