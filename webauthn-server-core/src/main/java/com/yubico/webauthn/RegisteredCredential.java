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

import com.yubico.webauthn.data.AttestedCredentialData;
import com.yubico.webauthn.data.AuthenticatorAssertionResponse;
import com.yubico.webauthn.data.AuthenticatorData;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.UserIdentity;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;


/**
 * An abstraction of a credential registered to a particular user.
 *
 * <p>
 * Instances of this class are not expected to be long-lived, and the library only needs to read them, never write them.
 * You may at your discretion store them directly in your database, or assemble them from other components.
 * </p>
 */
@Value
@AllArgsConstructor(access = AccessLevel.PRIVATE)
@Builder(toBuilder = true)
public class RegisteredCredential {

    /**
     * The <a href="https://www.w3.org/TR/2019/PR-webauthn-20190117/#credential-id">credential ID</a> of the
     * credential.
     *
     * @see <a href="https://www.w3.org/TR/2019/PR-webauthn-20190117/#credential-id">Credential ID</a>
     * @see RegistrationResult#getKeyId()
     * @see PublicKeyCredentialDescriptor#getId()
     */
    @NonNull
    private final ByteArray credentialId;

    /**
     * The <a href="https://www.w3.org/TR/2019/PR-webauthn-20190117/#user-handle">user handle</a> of the user the
     * credential is registered to.
     *
     * @see <a href="https://www.w3.org/TR/2019/PR-webauthn-20190117/#user-handle">User Handle</a>
     * @see UserIdentity#getId()
     */
    @NonNull
    private final ByteArray userHandle;

    /**
     * The credential public key encoded in COSE_Key format, as defined in Section 7 of <a
     * href="https://tools.ietf.org/html/rfc8152">RFC 8152</a>.
     *
     * <p>
     * This is used to verify the {@link AuthenticatorAssertionResponse#getSignature() signature} in authentication
     * assertions.
     * </p>
     *
     * @see AttestedCredentialData#getCredentialPublicKey()
     * @see RegistrationResult#getPublicKeyCose()
     */
    @NonNull
    private final ByteArray publicKeyCose;

    /**
     * The stored <a href="https://www.w3.org/TR/2019/PR-webauthn-20190117/#signcount">signature count</a> of the
     * credential.
     *
     * <p>
     * This is used to validate the {@link AuthenticatorData#getSignatureCounter() signature counter} in authentication
     * assertions.
     * </p>
     *
     * @see <a href="https://www.w3.org/TR/2019/PR-webauthn-20190117/#sec-authenticator-data">§6.1. Authenticator
     * Data</a>
     * @see AuthenticatorData#getSignatureCounter()
     * @see AssertionResult#getSignatureCount()
     */
    @Builder.Default
    private final long signatureCount = 0;

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
                public RegisteredCredentialBuilder publicKeyCose(ByteArray publicKeyCose) {
                    return builder.publicKeyCose(publicKeyCose);
                }
            }
        }
    }

}
