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
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;


@Value
@Builder
public class PublicKeyCredential<A extends AuthenticatorResponse, B extends ClientExtensionOutputs> implements Credential {

    /**
     * This attribute is inherited from `Credential`, though PublicKeyCredential overrides `Credential`'s getter,
     * instead returning the base64url encoding of the [[rawId]].
     */
    @NonNull
    private final ByteArray id;

    /**
     * The authenticator's response to the client’s request to either create a public key credential, or generate an
     * authentication assertion.
     * <p>
     * If the PublicKeyCredential is created in response to create(), this attribute’s value will be an
     * [[AuthenticatorAttestationResponse]], otherwise, the PublicKeyCredential was created in response to get(), and
     * this attribute’s value will be an [[AuthenticatorAssertionResponse]].
     */
    @NonNull
    private final A response;

    /**
     * A map containing extension identifier → client extension output entries produced by the extension’s client
     * extension processing.
     */
    @NonNull
    private final B clientExtensionResults;

    /**
     * The PublicKeyCredential's type value is the string "public-key".
     */
    @NonNull
    @Builder.Default
    private final PublicKeyCredentialType type = PublicKeyCredentialType.PUBLIC_KEY;

    @JsonCreator
    private PublicKeyCredential(
        @NonNull @JsonProperty("id") ByteArray id,
        @NonNull @JsonProperty("response") A response,
        @NonNull @JsonProperty("clientExtensionResults") B clientExtensionResults,
        @NonNull @JsonProperty("type") PublicKeyCredentialType type
    ) {
        this.id = id;
        this.response = response;
        this.clientExtensionResults = clientExtensionResults;
        this.type = type;
    }

}
