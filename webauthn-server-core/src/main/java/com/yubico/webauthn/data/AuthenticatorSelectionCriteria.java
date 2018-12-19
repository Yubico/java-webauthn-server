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
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;


/**
 * This class may be used to specify requirements regarding authenticator attributes.
 *
 * Note: The member identifiers are intentionally short, rather than descriptive, because they will be serialized into a
 * message to the authenticator, which may be sent over a low-bandwidth link.
 */
@Value
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder(toBuilder = true)
public class AuthenticatorSelectionCriteria {

    /**
     * If present, eligible authenticators are filtered to only authenticators attached with the specified §4.4.4
     * Authenticator Attachment enumeration.
     */
    @NonNull
    @Builder.Default
    private final Optional<AuthenticatorAttachment> authenticatorAttachment = Optional.empty();

    /**
     * requireResidentKey Describes the Relying Party's requirements regarding availability of the Client-side-resident
     * Credential Private Key. If the parameter is set to true, the authenticator MUST create a Client-side-resident
     * Credential Private Key when creating a public key credential.
     */
    @Builder.Default
    private final boolean requireResidentKey = false;

    /**
     * requireUserVerification
     * <p>
     * This member describes the Relying Party's requirements regarding user verification for the create() operation.
     * Eligible authenticators are filtered to only those capable of satisfying this requirement.
     */
    @NonNull
    @Builder.Default
    private UserVerificationRequirement userVerification = UserVerificationRequirement.PREFERRED;

    @JsonCreator
    private AuthenticatorSelectionCriteria(
        @JsonProperty("authenticatorAttachment") AuthenticatorAttachment authenticatorAttachment,
        @JsonProperty("requireResidentKey") boolean requireResidentKey,
        @NonNull @JsonProperty("userVerification") UserVerificationRequirement userVerification
    ) {
        this(Optional.ofNullable(authenticatorAttachment), requireResidentKey, userVerification);
    }

}
