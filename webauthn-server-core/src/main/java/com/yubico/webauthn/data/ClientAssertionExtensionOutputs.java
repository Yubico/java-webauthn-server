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
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;

/**
 * Contains <a href="https://www.w3.org/TR/2019/PR-webauthn-20190117/#client-extension-output">client extension
 * outputs</a> from a
 * <code>navigator.credentials.get()</code> operation.
 *
 * <p>
 * Note that there is no guarantee that any extension input present in {@link AssertionExtensionInputs} will have a
 * corresponding output present here.
 * </p>
 *
 * <p>
 * The authenticator extension outputs are contained in the {@link AuthenticatorData} structure.
 * </p>
 *
 * @see <a href="https://www.w3.org/TR/2019/PR-webauthn-20190117/#extensions">§9. WebAuthn Extensions</a>
 */
@Value
@Builder(toBuilder = true)
public class ClientAssertionExtensionOutputs implements ClientExtensionOutputs {

    /**
     * The output from the FIDO AppID Extension (<code>appid</code>).
     *
     * <p>
     * This value should be ignored because its behaviour is underspecified, see: <a
     * href="https://github.com/w3c/webauthn/issues/1034">https://github.com/w3c/webauthn/issues/1034</a>.
     * </p>
     *
     * @see <a href="https://www.w3.org/TR/2019/PR-webauthn-20190117/#sctn-appid-extension">§10.1. FIDO AppID Extension
     * (appid)</a>
     */
    @NonNull
    private final Optional<Boolean> appid;

    @JsonCreator
    private ClientAssertionExtensionOutputs(
        @NonNull @JsonProperty("appid") Optional<Boolean> appid
    ) {
        this.appid = appid;
    }

    @Override
    public Set<String> getExtensionIds() {
        Set<String> ids = new HashSet<>();

        appid.ifPresent((id) -> ids.add("appid"));

        return ids;
    }

    public static class ClientAssertionExtensionOutputsBuilder {
        private Optional<Boolean> appid = Optional.empty();

        /**
         * The output from the FIDO AppID Extension (<code>appid</code>).
         *
         * <p>
         * This value should be ignored because its behaviour is underspecified, see: <a
         * href="https://github.com/w3c/webauthn/issues/1034">https://github.com/w3c/webauthn/issues/1034</a>.
         * </p>
         *
         * @see <a href="https://www.w3.org/TR/2019/PR-webauthn-20190117/#sctn-appid-extension">§10.1. FIDO AppID Extension
         * (appid)</a>
         */
        public ClientAssertionExtensionOutputsBuilder appid(@NonNull Optional<Boolean> appid) {
            this.appid = appid;
            return this;
        }

        /**
         * The output from the FIDO AppID Extension (<code>appid</code>).
         *
         * <p>
         * This value should be ignored because its behaviour is underspecified, see: <a
         * href="https://github.com/w3c/webauthn/issues/1034">https://github.com/w3c/webauthn/issues/1034</a>.
         * </p>
         *
         * @see <a href="https://www.w3.org/TR/2019/PR-webauthn-20190117/#sctn-appid-extension">§10.1. FIDO AppID Extension
         * (appid)</a>
         */
        public ClientAssertionExtensionOutputsBuilder appid(boolean appid) {
            return this.appid(Optional.of(appid));
        }
    }
}
