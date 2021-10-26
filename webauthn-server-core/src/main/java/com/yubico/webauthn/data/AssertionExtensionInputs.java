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
 * Contains <a
 * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#client-extension-input">client
 * extension inputs</a> to a <code>navigator.credentials.get()</code> operation. All members are
 * optional.
 *
 * <p>The authenticator extension inputs are derived from these client extension inputs.
 *
 * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-extensions">§9. WebAuthn
 *     Extensions</a>
 */
@Value
@Builder(toBuilder = true)
@JsonIgnoreProperties(ignoreUnknown = true)
public class AssertionExtensionInputs implements ExtensionInputs {

  private final AppId appid;
  private final Extensions.LargeBlob.LargeBlobAuthenticationInput largeBlob;
  private final Boolean uvm;

  @JsonCreator
  private AssertionExtensionInputs(
      @JsonProperty("appid") AppId appid,
      @JsonProperty("largeBlob") Extensions.LargeBlob.LargeBlobAuthenticationInput largeBlob,
      @JsonProperty("uvm") Boolean uvm) {
    this.appid = appid;
    this.largeBlob = largeBlob;
    this.uvm = (uvm != null && uvm) ? true : null;
  }

  /**
   * Merge <code>other</code> into <code>this</code>. Non-null field values from <code>this</code>
   * take precedence.
   *
   * @return a new {@link AssertionExtensionInputs} instance with the settings from both <code>this
   *     </code> and <code>other</code>.
   */
  public AssertionExtensionInputs merge(AssertionExtensionInputs other) {
    return new AssertionExtensionInputs(
        this.appid != null ? this.appid : other.appid,
        this.largeBlob != null ? this.largeBlob : other.largeBlob,
        this.uvm != null ? this.uvm : other.uvm);
  }

  /**
   * @return The extension identifiers of all extensions configured.
   * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-extension-id">§9.1.
   *     Extension Identifiers</a>
   */
  @Override
  public Set<String> getExtensionIds() {
    Set<String> ids = new HashSet<>();
    if (appid != null) {
      ids.add(Extensions.Appid.EXTENSION_ID);
    }
    if (largeBlob != null) {
      ids.add(Extensions.LargeBlob.EXTENSION_ID);
    }
    if (getUvm()) {
      ids.add(Extensions.Uvm.EXTENSION_ID);
    }
    return ids;
  }

  public static class AssertionExtensionInputsBuilder {
    /**
     * The input to the FIDO AppID Extension (<code>appid</code>).
     *
     * <p>You usually do not need to call this method explicitly; if {@link RelyingParty#getAppId()}
     * is present, then {@link RelyingParty#startAssertion(StartAssertionOptions)} will enable this
     * extension automatically.
     *
     * <p>This extension allows WebAuthn Relying Parties that have previously registered a
     * credential using the legacy FIDO JavaScript APIs to request an assertion. The FIDO APIs use
     * an alternative identifier for Relying Parties called an <a
     * href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-appid-and-facets-v2.0-id-20180227.html">AppID</a>,
     * and any credentials created using those APIs will be scoped to that identifier. Without this
     * extension, they would need to be re-registered in order to be scoped to an RP ID.
     *
     * <p>This extension does not allow FIDO-compatible credentials to be created. Thus, credentials
     * created with WebAuthn are not backwards compatible with the FIDO JavaScript APIs.
     *
     * @see <a
     *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-appid-extension">§10.1.
     *     FIDO AppID Extension (appid)</a>
     */
    public AssertionExtensionInputsBuilder appid(@NonNull Optional<AppId> appid) {
      return this.appid(appid.orElse(null));
    }

    /**
     * The input to the FIDO AppID Extension (<code>appid</code>).
     *
     * <p>You usually do not need to call this method explicitly; if {@link RelyingParty#getAppId()}
     * is present, then {@link RelyingParty#startAssertion(StartAssertionOptions)} will enable this
     * extension automatically.
     *
     * <p>This extension allows WebAuthn Relying Parties that have previously registered a
     * credential using the legacy FIDO JavaScript APIs to request an assertion. The FIDO APIs use
     * an alternative identifier for Relying Parties called an <a
     * href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-appid-and-facets-v2.0-id-20180227.html">AppID</a>,
     * and any credentials created using those APIs will be scoped to that identifier. Without this
     * extension, they would need to be re-registered in order to be scoped to an RP ID.
     *
     * <p>This extension does not allow FIDO-compatible credentials to be created. Thus, credentials
     * created with WebAuthn are not backwards compatible with the FIDO JavaScript APIs.
     *
     * @see <a
     *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-appid-extension">§10.1.
     *     FIDO AppID Extension (appid)</a>
     */
    public AssertionExtensionInputsBuilder appid(AppId appid) {
      this.appid = appid;
      return this;
    }

    /**
     * Enable the Large blob storage extension (<code>largeBlob</code>).
     *
     * <p>Suitable arguments can be obtained using {@link
     * Extensions.LargeBlob.LargeBlobAuthenticationInput#read()} or {@link
     * Extensions.LargeBlob.LargeBlobAuthenticationInput#write(ByteArray)}.
     *
     * @see Extensions.LargeBlob.LargeBlobAuthenticationInput#read()
     * @see Extensions.LargeBlob.LargeBlobAuthenticationInput#write(ByteArray)
     * @see <a
     *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-large-blob-extension">§10.5.
     *     Large blob storage extension (largeBlob)</a>
     */
    public AssertionExtensionInputsBuilder largeBlob(
        Extensions.LargeBlob.LargeBlobAuthenticationInput largeBlob) {
      this.largeBlob = largeBlob;
      return this;
    }

    /**
     * Enable the User Verification Method Extension (<code>uvm</code>).
     *
     * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-uvm-extension">§10.3.
     *     User Verification Method Extension (uvm)</a>
     */
    public AssertionExtensionInputsBuilder uvm() {
      this.uvm = true;
      return this;
    }

    /** For compatibility with {@link Builder}(toBuilder = true) */
    private AssertionExtensionInputsBuilder uvm(Boolean uvm) {
      this.uvm = uvm;
      return this;
    }
  }

  /**
   * The input to the FIDO AppID Extension (<code>appid</code>).
   *
   * <p>This extension allows WebAuthn Relying Parties that have previously registered a credential
   * using the legacy FIDO JavaScript APIs to request an assertion. The FIDO APIs use an alternative
   * identifier for Relying Parties called an <a
   * href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-appid-and-facets-v2.0-id-20180227.html">AppID</a>,
   * and any credentials created using those APIs will be scoped to that identifier. Without this
   * extension, they would need to be re-registered in order to be scoped to an RP ID.
   *
   * <p>This extension does not allow FIDO-compatible credentials to be created. Thus, credentials
   * created with WebAuthn are not backwards compatible with the FIDO JavaScript APIs.
   *
   * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-appid-extension">§10.1.
   *     FIDO AppID Extension (appid)</a>
   */
  public Optional<AppId> getAppid() {
    return Optional.ofNullable(appid);
  }

  /**
   * The input to the Large blob storage extension (<code>largeBlob</code>).
   *
   * <p>This extension allows a Relying Party to store opaque data associated with a credential.
   *
   * @see Extensions.LargeBlob.LargeBlobAuthenticationInput#read()
   * @see Extensions.LargeBlob.LargeBlobAuthenticationInput#write(ByteArray)
   * @see <a
   *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-large-blob-extension">§10.5.
   *     Large blob storage extension (largeBlob)</a>
   */
  public Optional<Extensions.LargeBlob.LargeBlobAuthenticationInput> getLargeBlob() {
    return Optional.ofNullable(largeBlob);
  }

  /** For JSON serialization, to omit false and null values. */
  @JsonProperty("largeBlob")
  private Extensions.LargeBlob.LargeBlobAuthenticationInput getLargeBlobJson() {
    return largeBlob != null && (largeBlob.getRead() || largeBlob.getWrite().isPresent())
        ? largeBlob
        : null;
  }

  /**
   * @return <code>true</code> if the User Verification Method Extension (<code>uvm</code>) is
   *     enabled, <code>false</code> otherwise.
   * @see AssertionExtensionInputsBuilder#uvm()
   * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-uvm-extension">§10.3.
   *     User Verification Method Extension (uvm)</a>
   */
  public boolean getUvm() {
    return uvm != null && uvm;
  }

  /** For JSON serialization, to omit false values. */
  @JsonProperty("uvm")
  private Boolean getUvmJson() {
    return getUvm() ? true : null;
  }
}
