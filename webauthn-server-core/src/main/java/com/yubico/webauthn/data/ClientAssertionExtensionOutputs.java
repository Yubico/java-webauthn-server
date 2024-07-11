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
import lombok.NonNull;
import lombok.Value;

/**
 * Contains <a
 * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#client-extension-output">client
 * extension outputs</a> from a <code>navigator.credentials.get()</code> operation.
 *
 * <p>Note that there is no guarantee that any extension input present in {@link
 * AssertionExtensionInputs} will have a corresponding output present here.
 *
 * <p>The authenticator extension outputs are contained in the {@link AuthenticatorData} structure.
 *
 * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-extensions">§9. WebAuthn
 *     Extensions</a>
 */
@Value
@Builder(toBuilder = true)
@JsonIgnoreProperties(ignoreUnknown = true)
public class ClientAssertionExtensionOutputs implements ClientExtensionOutputs {

  /**
   * The extension output for the FIDO AppID Extension (<code>appid</code>), if any.
   *
   * <p>This value should be ignored because its behaviour is underspecified, see: <a
   * href="https://github.com/w3c/webauthn/issues/1034">https://github.com/w3c/webauthn/issues/1034</a>.
   *
   * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-appid-extension">§10.1.
   *     FIDO AppID Extension (appid)</a>
   */
  private final Boolean appid;

  private final Extensions.CredentialProperties.CredentialPropertiesOutput credProps;

  private final Extensions.LargeBlob.LargeBlobAuthenticationOutput largeBlob;

  @JsonCreator
  private ClientAssertionExtensionOutputs(
      @JsonProperty("appid") Boolean appid,
      @JsonProperty("credProps")
          Extensions.CredentialProperties.CredentialPropertiesOutput credProps,
      @JsonProperty("largeBlob") Extensions.LargeBlob.LargeBlobAuthenticationOutput largeBlob) {
    this.appid = appid;
    this.credProps = credProps;
    this.largeBlob = largeBlob;
  }

  @Override
  @EqualsAndHashCode.Include
  public Set<String> getExtensionIds() {
    HashSet<String> ids = new HashSet<>();
    if (appid != null) {
      ids.add(Extensions.Appid.EXTENSION_ID);
    }
    if (credProps != null) {
      ids.add(Extensions.CredentialProperties.EXTENSION_ID);
    }
    if (largeBlob != null) {
      ids.add(Extensions.LargeBlob.EXTENSION_ID);
    }
    return ids;
  }

  /**
   * The extension output for the FIDO AppID Extension (<code>appid</code>), if any.
   *
   * <p>This value should be ignored because its behaviour is underspecified, see: <a
   * href="https://github.com/w3c/webauthn/issues/1034">https://github.com/w3c/webauthn/issues/1034</a>.
   *
   * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-appid-extension">§10.1.
   *     FIDO AppID Extension (appid)</a>
   */
  public Optional<Boolean> getAppid() {
    return Optional.ofNullable(appid);
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
   * @deprecated EXPERIMENTAL: This feature is from a not yet mature standard; it could change as
   *     the standard matures.
   */
  @Deprecated
  public Optional<Extensions.CredentialProperties.CredentialPropertiesOutput> getCredProps() {
    return Optional.ofNullable(credProps);
  }

  /**
   * The extension output for the <a
   * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-large-blob-extension">Large blob
   * storage (<code>largeBlob</code>) extension</a>, if any.
   *
   * @see com.yubico.webauthn.data.Extensions.LargeBlob.LargeBlobRegistrationOutput
   * @see <a
   *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-large-blob-extension">§10.5.Large
   *     blob storage extension (largeBlob)</a>
   */
  public Optional<Extensions.LargeBlob.LargeBlobAuthenticationOutput> getLargeBlob() {
    return Optional.ofNullable(largeBlob);
  }

  public static class ClientAssertionExtensionOutputsBuilder {

    /**
     * The extension output for the FIDO AppID Extension (<code>appid</code>).
     *
     * <p>This value should be ignored because its behaviour is underspecified, see: <a
     * href="https://github.com/w3c/webauthn/issues/1034">https://github.com/w3c/webauthn/issues/1034</a>.
     *
     * @see <a
     *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-appid-extension">§10.1.
     *     FIDO AppID Extension (appid)</a>
     */
    public ClientAssertionExtensionOutputsBuilder appid(@NonNull Optional<Boolean> appid) {
      this.appid = appid.orElse(null);
      return this;
    }

    /*
     * Workaround, see: https://github.com/rzwitserloot/lombok/issues/2623#issuecomment-714816001
     * Consider reverting this workaround if Lombok fixes that issue.
     */
    private ClientAssertionExtensionOutputsBuilder appid(Boolean appid) {
      return this.appid(Optional.ofNullable(appid));
    }

    /**
     * The extension output for the FIDO AppID Extension (<code>appid</code>).
     *
     * <p>This value should be ignored because its behaviour is underspecified, see: <a
     * href="https://github.com/w3c/webauthn/issues/1034">https://github.com/w3c/webauthn/issues/1034</a>.
     *
     * @see <a
     *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-appid-extension">§10.1.
     *     FIDO AppID Extension (appid)</a>
     */
    public ClientAssertionExtensionOutputsBuilder appid(boolean appid) {
      return this.appid(Optional.of(appid));
    }
  }
}
