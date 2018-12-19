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
 * Describes a user account, with which a public key credential is to be associated.
 */
@Value
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder(toBuilder = true)
public class UserIdentity implements PublicKeyCredentialEntity {

    /**
     * A name for the user account.
     * <p>
     * For example: "john.p.smith@example.com" or "+14255551234".
     */
    @NonNull
    private final String name;

    /**
     * A friendly name for the user account (e.g. "Ryan A. Smith").
     */
    @NonNull
    private final String displayName;

    /**
     * An identifier for the account, specified by the Relying Party.
     * <p>
     * This is not meant to be displayed to the user, but is used by the Relying Party to control the number of
     * credentials - an authenticator will never contain more than one credential for a given Relying Party under the
     * same id.
     */
    @NonNull
    private final ByteArray id;

    /**
     * A URL which resolves to an image associated with the user account.
     * <p>
     * For example, this could be the user's avatar.
     */
    @NonNull
    @Builder.Default
    private final Optional<URL> icon = Optional.empty();

    @JsonCreator
    private UserIdentity(
        @NonNull @JsonProperty("name") String name,
        @NonNull @JsonProperty("displayName") String displayName,
        @NonNull @JsonProperty("id") ByteArray id,
        @JsonProperty("icon") URL icon
    ) {
        this(name, displayName, id, Optional.ofNullable(icon));
    }

    public static UserIdentityBuilder.MandatoryStages builder() {
        return new UserIdentityBuilder.MandatoryStages();
    }

    public static class UserIdentityBuilder {
        public static class MandatoryStages {
            private UserIdentityBuilder builder = new UserIdentityBuilder();

            public Step2 name(String name) {
                builder.name(name);
                return new Step2();
            }

            public class Step2 {
                public Step3 displayName(String displayName) {
                    builder.displayName(displayName);
                    return new Step3();
                }
            }

            public class Step3 {
                public UserIdentityBuilder id(ByteArray id) {
                    return builder.id(id);
                }

            }
        }
    }

}
