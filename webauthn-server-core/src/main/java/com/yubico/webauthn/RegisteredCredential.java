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

import com.yubico.webauthn.data.ByteArray;
import java.security.PublicKey;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;


@Value
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
public class RegisteredCredential {

    @NonNull
    private final ByteArray credentialId;

    @NonNull
    private final ByteArray userHandle;

    @NonNull
    public final PublicKey publicKey;

    @Builder.Default
    public final long signatureCount = 0;

    public static RegisteredCredentialBuilder.MandatoryStages builder() {
        return new RegisteredCredentialBuilder.MandatoryStages();
    }

    public static class RegisteredCredentialBuilder {
        public static class MandatoryStages {
            private RegisteredCredentialBuilder builder = new RegisteredCredentialBuilder();
            public Step2 credentialId(ByteArray credentialId) {
                builder.credentialId(credentialId);
                return new Step2();
            }
            public class Step2 {
                public Step3 userHandle(ByteArray userHandle) {
                    builder.userHandle(userHandle);
                    return new Step3();
                }
            }
            public class Step3 {
                public RegisteredCredentialBuilder publicKey(PublicKey publicKey) {
                    return builder.publicKey(publicKey);
                }
            }
        }
    }

}
