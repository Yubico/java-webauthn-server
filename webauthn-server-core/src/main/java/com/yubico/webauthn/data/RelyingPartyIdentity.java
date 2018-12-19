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
import java.net.URL;
import java.util.Optional;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;


/**
 * Describes a Relying Party with which a public key credential is associated.
 */
@Value
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder(toBuilder = true)
public class RelyingPartyIdentity implements PublicKeyCredentialEntity {

    /**
     * The human-friendly name of the Relaying Party.
     *
     * For example: "Acme Corporation", "Widgets, Inc.", or "Awesome Site".
     */
    @NonNull
    private final String name;

    /**
     * The RP identifier with which credentials are associated.
     */
    @NonNull
    private final String id;

    /**
     * A URL which resolves to an image associated with the RP.
     *
     * For example, this could be the RP's logo.
     */
    @NonNull
    @Builder.Default
    private final Optional<URL> icon = Optional.empty();

    @JsonCreator
    private RelyingPartyIdentity(
        @NonNull @JsonProperty("name") String name,
        @NonNull @JsonProperty("id") String id,
        @JsonProperty("icon") URL icon
    ) {
        this(name, id, Optional.ofNullable(icon));
    }

    public static RelyingPartyIdentityBuilder.MandatoryStages builder() {
        return new RelyingPartyIdentityBuilder.MandatoryStages();
    }

    public static class RelyingPartyIdentityBuilder {
        public static class MandatoryStages {
            private RelyingPartyIdentityBuilder builder = new RelyingPartyIdentityBuilder();

            public Step2 id(String id) {
                builder.id(id);
                return new Step2();
            }

            public class Step2 {
                public RelyingPartyIdentityBuilder name(String name) {
                    return builder.name(name);
                }
            }
        }
    }

}
