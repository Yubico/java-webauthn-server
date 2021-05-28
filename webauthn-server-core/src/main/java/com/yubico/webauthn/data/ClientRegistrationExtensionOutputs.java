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
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Value;
import lombok.extern.slf4j.Slf4j;

/**
 * Contains <a
 * href="https://www.w3.org/TR/2019/PR-webauthn-20190117/#client-extension-output">client extension
 * outputs</a> from a <code>navigator.credentials.create()</code> operation.
 *
 * <p>Note that there is no guarantee that any extension input present in {@link
 * AssertionExtensionInputs} will have a corresponding output present here.
 *
 * <p>The authenticator extension outputs are contained in the {@link AuthenticatorData} structure.
 *
 * @see <a href="https://www.w3.org/TR/2019/PR-webauthn-20190117/#extensions">§9. WebAuthn
 *     Extensions</a>
 */
@Value
@Builder(toBuilder = true)
@Slf4j
@JsonIgnoreProperties(ignoreUnknown = true)
public class ClientRegistrationExtensionOutputs implements ClientExtensionOutputs {

  private final boolean appidExclude;

  private final Extensions.CredentialProperties.CredentialPropertiesOutput credProps;

  private final Extensions.LargeBlob.LargeBlobRegistrationOutput largeBlob;

  @JsonCreator
  private ClientRegistrationExtensionOutputs(
      @JsonProperty("appidExclude") boolean appidExclude,
      @JsonProperty("credProps")
          Extensions.CredentialProperties.CredentialPropertiesOutput credProps,
      @JsonProperty("largeBlob") Extensions.LargeBlob.LargeBlobRegistrationOutput largeBlob) {
    this.appidExclude = appidExclude;
    this.credProps = credProps;
    this.largeBlob = largeBlob;
  }

  @Override
  @EqualsAndHashCode.Include
  public Set<String> getExtensionIds() {
    HashSet<String> ids = new HashSet<>();
    if (appidExclude) {
      ids.add(Extensions.AppidExclude.EXTENSION_ID);
    }
    if (credProps != null) {
      ids.add(Extensions.CredentialProperties.EXTENSION_ID);
    }
    if (largeBlob != null) {
      ids.add(Extensions.LargeBlob.EXTENSION_ID);
    }
    return ids;
  }

  public boolean getAppidExclude() {
    return appidExclude;
  }

  /** For JSON serialization, to omit false values. */
  @JsonProperty("appidExclude")
  private Boolean getAppidExcludeJson() {
    return appidExclude ? true : null;
  }

  /**
   * The extension output for the Credential Properties Extension (<code>credProps</code>), if any.
   *
   * <p>This value MAY be present but have all members empty if the extension was successfully
   * processed but no credential properties could be determined.
   *
   * @see com.yubico.webauthn.data.Extensions.CredentialProperties.CredentialPropertiesOutput
   * @see <a
   *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-authenticator-credential-properties-extension">§10.4.
   *     Credential Properties Extension (credProps)</a>
   */
  public Optional<Extensions.CredentialProperties.CredentialPropertiesOutput> getCredProps() {
    return Optional.ofNullable(credProps);
  }

  public Optional<Extensions.LargeBlob.LargeBlobRegistrationOutput> getLargeBlob() {
    return Optional.ofNullable(largeBlob);
  }
}
