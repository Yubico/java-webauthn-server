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
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;


/**
 * The PublicKeyCredentialRequestOptions dictionary supplies get() with the data it needs to generate an assertion.
 * <p>
 * Its `challenge` member must be present, while its other members are optional.
 */
@Value
@Builder(toBuilder = true)
public class PublicKeyCredentialRequestOptions {

    /**
     * A challenge that the selected authenticator signs, along with other data, when producing an authentication
     * assertion.
     */
    @NonNull
    private final ByteArray challenge;

    /**
     * Specifies a time, in milliseconds, that the caller is willing to wait for the call to complete.
     * <p>
     * This is treated as a hint, and MAY be overridden by the platform.
     */
    @NonNull
    @Builder.Default
    private final Optional<Long> timeout = Optional.empty();

    /**
     * Specifies the relying party identifier claimed by the caller.
     * <p>
     * If omitted, its value will be set by the client.
     */
    @NonNull
    @Builder.Default
    private final Optional<String> rpId = Optional.empty();

    /**
     * A list of public key credentials acceptable to the caller, in descending order of the caller’s preference.
     */
    @NonNull
    @Builder.Default
    private final Optional<List<PublicKeyCredentialDescriptor>> allowCredentials = Optional.empty();

    /**
     * Describes the Relying Party's requirements regarding user verification for the get() operation.
     * <p>
     * Eligible authenticators are filtered to only those capable of satisfying this requirement.
     */
    @NonNull
    @Builder.Default
    private final UserVerificationRequirement userVerification = UserVerificationRequirement.DEFAULT;

    /**
     * Additional parameters requesting additional processing by the client and authenticator.
     * <p>
     * For example, if transaction confirmation is sought from the user, then the prompt string might be included as an
     * extension.
     */
    @NonNull
    @Builder.Default
    private final AssertionExtensionInputs extensions = AssertionExtensionInputs.builder().build();

    private PublicKeyCredentialRequestOptions(
        @NonNull ByteArray challenge,
        @NonNull Optional<Long> timeout,
        @NonNull Optional<String> rpId,
        @NonNull Optional<List<PublicKeyCredentialDescriptor>> allowCredentials,
        @NonNull UserVerificationRequirement userVerification,
        @NonNull AssertionExtensionInputs extensions
    ) {
        this.challenge = challenge;
        this.timeout = timeout;
        this.rpId = rpId;
        this.allowCredentials = allowCredentials.map(Collections::unmodifiableList);
        this.userVerification = userVerification;
        this.extensions = extensions;
    }

    @JsonCreator
    private PublicKeyCredentialRequestOptions(
        @NonNull @JsonProperty("challenge") ByteArray challenge,
        @JsonProperty("timeout") Long timeout,
        @JsonProperty("rpId") String rpId,
        @JsonProperty("allowCredentials") List<PublicKeyCredentialDescriptor> allowCredentials,
        @NonNull @JsonProperty("userVerification") UserVerificationRequirement userVerification,
        @JsonProperty("extensions") AssertionExtensionInputs extensions
    ) {
        this(
            challenge,
            Optional.ofNullable(timeout),
            Optional.ofNullable(rpId),
            Optional.ofNullable(allowCredentials),
            userVerification,
            Optional.ofNullable(extensions).orElseGet(() -> AssertionExtensionInputs.builder().build())
        );
    }

    public static PublicKeyCredentialRequestOptionsBuilder.MandatoryStages builder() {
        return new PublicKeyCredentialRequestOptionsBuilder.MandatoryStages();
    }

    public static class PublicKeyCredentialRequestOptionsBuilder {
        public static class MandatoryStages {
            private PublicKeyCredentialRequestOptionsBuilder builder = new PublicKeyCredentialRequestOptionsBuilder();

            public PublicKeyCredentialRequestOptionsBuilder challenge(ByteArray challenge) {
                return builder.challenge(challenge);
            }
        }
    }
}
