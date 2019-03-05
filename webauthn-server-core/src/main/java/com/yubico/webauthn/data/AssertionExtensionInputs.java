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
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartAssertionOptions;
import com.yubico.webauthn.extension.appid.AppId;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;

/**
 * Contains <a href="https://www.w3.org/TR/2019/PR-webauthn-20190117/#client-extension-input">client extension
 * inputs</a> to a
 * <code>navigator.credentials.get()</code> operation. All members are optional.
 *
 * <p>
 * The authenticator extension inputs are derived from these client extension inputs.
 * </p>
 *
 * @see <a href="https://www.w3.org/TR/2019/PR-webauthn-20190117/#extensions">§9. WebAuthn Extensions</a>
 */
@Value
@Builder(toBuilder = true)
public class AssertionExtensionInputs implements ExtensionInputs {

    /**
     * The input to the FIDO AppID Extension (<code>appid</code>).
     *
     * <p>
     * This extension allows WebAuthn Relying Parties that have previously registered a credential using the legacy FIDO
     * JavaScript APIs to request an assertion. The FIDO APIs use an alternative identifier for Relying Parties called
     * an <a href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-appid-and-facets-v2.0-id-20180227.html">AppID</a>,
     * and any credentials created using those APIs will be scoped to that identifier. Without this extension, they
     * would need to be re-registered in order to be scoped to an RP ID.
     * </p>
     * <p>
     * This extension does not allow FIDO-compatible credentials to be created. Thus, credentials created with WebAuthn
     * are not backwards compatible with the FIDO JavaScript APIs.
     * </p>
     *
     * <p>
     * {@link RelyingParty#startAssertion(StartAssertionOptions)} sets this extension input automatically if the {@link
     * RelyingParty.RelyingPartyBuilder#appId(Optional)} parameter is given when constructing the {@link RelyingParty}
     * instance.
     * </p>
     *
     * @see <a href="https://www.w3.org/TR/2019/PR-webauthn-20190117/#sctn-appid-extension">§10.1. FIDO AppID Extension
     * (appid)</a>
     */
    @NonNull
    private final Optional<AppId> appid;

    @JsonCreator
    private AssertionExtensionInputs(
        @NonNull @JsonProperty("appid") Optional<AppId> appid
    ) {
        this.appid = appid;
    }

    @Override
    public Set<String> getExtensionIds() {
        Set<String> ids = new HashSet<>();

        appid.ifPresent((id) -> ids.add("appid"));

        return ids;
    }

    public static class AssertionExtensionInputsBuilder {
        private Optional<AppId> appid = Optional.empty();

        /**
         * The input to the FIDO AppID Extension (<code>appid</code>).
         *
         * <p>
         * This extension allows WebAuthn Relying Parties that have previously registered a credential using the legacy FIDO
         * JavaScript APIs to request an assertion. The FIDO APIs use an alternative identifier for Relying Parties called
         * an <a href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-appid-and-facets-v2.0-id-20180227.html">AppID</a>,
         * and any credentials created using those APIs will be scoped to that identifier. Without this extension, they
         * would need to be re-registered in order to be scoped to an RP ID.
         * </p>
         * <p>
         * This extension does not allow FIDO-compatible credentials to be created. Thus, credentials created with WebAuthn
         * are not backwards compatible with the FIDO JavaScript APIs.
         * </p>
         *
         * <p>
         * {@link RelyingParty#startAssertion(StartAssertionOptions)} sets this extension input automatically if the {@link
         * RelyingParty.RelyingPartyBuilder#appId(Optional)} parameter is given when constructing the {@link RelyingParty}
         * instance.
         * </p>
         *
         * @see <a href="https://www.w3.org/TR/2019/PR-webauthn-20190117/#sctn-appid-extension">§10.1. FIDO AppID Extension
         * (appid)</a>
         */
        public AssertionExtensionInputsBuilder appid(@NonNull Optional<AppId> appid) {
            this.appid = appid;
            return this;
        }

        /**
         * The input to the FIDO AppID Extension (<code>appid</code>).
         *
         * <p>
         * This extension allows WebAuthn Relying Parties that have previously registered a credential using the legacy FIDO
         * JavaScript APIs to request an assertion. The FIDO APIs use an alternative identifier for Relying Parties called
         * an <a href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-appid-and-facets-v2.0-id-20180227.html">AppID</a>,
         * and any credentials created using those APIs will be scoped to that identifier. Without this extension, they
         * would need to be re-registered in order to be scoped to an RP ID.
         * </p>
         * <p>
         * This extension does not allow FIDO-compatible credentials to be created. Thus, credentials created with WebAuthn
         * are not backwards compatible with the FIDO JavaScript APIs.
         * </p>
         *
         * <p>
         * {@link RelyingParty#startAssertion(StartAssertionOptions)} sets this extension input automatically if the {@link
         * RelyingParty.RelyingPartyBuilder#appId(Optional)} parameter is given when constructing the {@link RelyingParty}
         * instance.
         * </p>
         *
         * @see <a href="https://www.w3.org/TR/2019/PR-webauthn-20190117/#sctn-appid-extension">§10.1. FIDO AppID Extension
         * (appid)</a>
         */
        public AssertionExtensionInputsBuilder appid(@NonNull AppId appid) {
            return this.appid(Optional.of(appid));
        }
    }
}
