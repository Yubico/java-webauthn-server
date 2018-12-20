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
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.yubico.webauthn.data.exception.Base64UrlException;
import java.io.IOException;
import lombok.Builder;
import lombok.Getter;
import lombok.NonNull;
import lombok.Value;


@Value
public class AuthenticatorAttestationResponse implements AuthenticatorResponse {

    @NonNull
    private final ByteArray attestationObject;

    @NonNull
    @Getter(onMethod = @__({ @Override }))
    private final ByteArray clientDataJSON;

    @NonNull
    @JsonIgnore
    private final transient AttestationObject attestation;

    @NonNull
    @JsonIgnore
    @Getter(onMethod = @__({ @Override }))
    private final transient CollectedClientData clientData;

    @Override
    @JsonIgnore
    public ByteArray getAuthenticatorData() {
        return attestation.getAuthenticatorData().getBytes();
    }

    @Builder(toBuilder = true)
    @JsonCreator
    private AuthenticatorAttestationResponse(
        @NonNull @JsonProperty("attestationObject") ByteArray attestationObject,
        @NonNull @JsonProperty("clientDataJSON") ByteArray clientDataJSON
    ) throws IOException, Base64UrlException {
        this.attestationObject = attestationObject;
        this.clientDataJSON = clientDataJSON;

        attestation = new AttestationObject(attestationObject);
        this.clientData = new CollectedClientData(clientDataJSON);
    }

    public static AuthenticatorAttestationResponseBuilder.MandatoryStages builder() {
        return new AuthenticatorAttestationResponseBuilder.MandatoryStages();
    }

    public static class AuthenticatorAttestationResponseBuilder {
        public static class MandatoryStages {
            private final AuthenticatorAttestationResponseBuilder builder = new AuthenticatorAttestationResponseBuilder();

            public Step2 attestationObject(ByteArray attestationObject) {
                builder.attestationObject(attestationObject);
                return new Step2();
            }

            public class Step2 {
                public AuthenticatorAttestationResponseBuilder clientDataJSON(ByteArray clientDataJSON) {
                    return builder.clientDataJSON(clientDataJSON);
                }
            }
        }
    }

}
