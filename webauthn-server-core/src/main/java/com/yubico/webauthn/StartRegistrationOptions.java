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
import com.yubico.webauthn.data.RegistrationExtensionInputs;
import com.yubico.webauthn.data.UserIdentity;
import java.util.Optional;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;

/**
 * Parameters for {@link RelyingParty#startRegistration(StartRegistrationOptions)}.
 */
@Value
@Builder(toBuilder = true)
public class StartRegistrationOptions {

    /**
     * Identifiers for the user creating a credential.
     */
    @NonNull
    private final UserIdentity user;

    /**
     * Constraints on what kind of authenticator the user is allowed to use to create the credential.
     */
    @NonNull
    @Builder.Default
    private final Optional<AuthenticatorSelectionCriteria> authenticatorSelection = Optional.empty();

    /**
     * Extension inputs for this registration operation.
     */
    @NonNull
    @Builder.Default
    private final RegistrationExtensionInputs extensions = RegistrationExtensionInputs.builder().build();

    public static StartRegistrationOptionsBuilder.MandatoryStages builder() {
        return new StartRegistrationOptionsBuilder.MandatoryStages();
    }

    public static class StartRegistrationOptionsBuilder {
        public static class MandatoryStages {
            private final StartRegistrationOptionsBuilder builder = new StartRegistrationOptionsBuilder();

            public StartRegistrationOptionsBuilder user(UserIdentity user) {
                return builder.user(user);
            }
        }
    }

}
