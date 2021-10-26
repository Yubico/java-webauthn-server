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
import com.yubico.webauthn.StartRegistrationOptions;
import com.yubico.webauthn.extension.appid.AppId;
import java.util.Collections;
import java.util.HashSet;
import java.util.Optional;
import java.util.Set;
import lombok.Builder;
import lombok.Value;

/**
 * Contains <a
 * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#client-extension-input">client
 * extension inputs</a> to a <code>navigator.credentials.create()</code> operation. All members are
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
public final class RegistrationExtensionInputs implements ExtensionInputs {

  private final AppId appidExclude;
  private final Boolean credProps;
  private final Extensions.LargeBlob.LargeBlobRegistrationInput largeBlob;
  private final Boolean uvm;

  @JsonCreator
  private RegistrationExtensionInputs(
      @JsonProperty("appidExclude") AppId appidExclude,
      @JsonProperty("credProps") Boolean credProps,
      @JsonProperty("largeBlob") Extensions.LargeBlob.LargeBlobRegistrationInput largeBlob,
      @JsonProperty("uvm") Boolean uvm) {
    this.appidExclude = appidExclude;
    this.credProps = credProps;
    this.largeBlob = largeBlob;
    this.uvm = uvm;
  }

  /**
   * Merge <code>other</code> into <code>this</code>. Non-null field values from <code>this</code>
   * take precedence.
   *
   * @return a new {@link RegistrationExtensionInputs} instance with the settings from both <code>
   *     this</code> and <code>other</code>.
   */
  public RegistrationExtensionInputs merge(RegistrationExtensionInputs other) {
    return new RegistrationExtensionInputs(
        this.appidExclude != null ? this.appidExclude : other.appidExclude,
        this.credProps != null ? this.credProps : other.credProps,
        this.largeBlob != null ? this.largeBlob : other.largeBlob,
        this.uvm != null ? this.uvm : other.uvm);
  }

  /**
   * @return The value of the FIDO AppID Exclusion Extension (<code>appidExclude</code>) input if
   *     configured, empty otherwise.
   * @see RegistrationExtensionInputsBuilder#appidExclude(AppId)
   * @see <a
   *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-appid-exclude-extension">§10.2.
   *     FIDO AppID Exclusion Extension (appidExclude)</a>
   */
  public Optional<AppId> getAppidExclude() {
    return Optional.ofNullable(appidExclude);
  }

  /**
   * @return <code>true</code> if the Credential Properties Extension (<code>credProps</code>) is
   *     enabled, <code>false</code> otherwise.
   * @see RegistrationExtensionInputsBuilder#credProps()
   * @see <a
   *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-authenticator-credential-properties-extension">§10.4.
   *     Credential Properties Extension (credProps)</a>
   */
  public boolean getCredProps() {
    return credProps != null && credProps;
  }

  /** For JSON serialization, to omit false values. */
  @JsonProperty("credProps")
  private Boolean getCredPropsJson() {
    return getCredProps() ? true : null;
  }

  /**
   * @return The value of the Large blob storage extension (<code>largeBlob</code>) input if
   *     configured, empty otherwise.
   * @see
   *     RegistrationExtensionInputsBuilder#largeBlob(Extensions.LargeBlob.LargeBlobRegistrationInput)
   * @see
   *     RegistrationExtensionInputsBuilder#largeBlob(Extensions.LargeBlob.LargeBlobRegistrationInput.LargeBlobSupport)
   * @see <a
   *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-large-blob-extension">§10.5.
   *     Large blob storage extension (largeBlob)</a>
   */
  public Optional<Extensions.LargeBlob.LargeBlobRegistrationInput> getLargeBlob() {
    return Optional.ofNullable(largeBlob);
  }

  /**
   * @return <code>true</code> if the User Verification Method Extension (<code>uvm</code>) is
   *     enabled, <code>false</code> otherwise.
   * @see RegistrationExtensionInputsBuilder#uvm()
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

  /**
   * @return The extension identifiers of all extensions configured.
   * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-extension-id">§9.1.
   *     Extension Identifiers</a>
   */
  @Override
  public Set<String> getExtensionIds() {
    Set<String> ids = new HashSet<>();
    if (appidExclude != null) {
      ids.add(Extensions.AppidExclude.EXTENSION_ID);
    }
    if (getCredProps()) {
      ids.add(Extensions.CredentialProperties.EXTENSION_ID);
    }
    if (largeBlob != null) {
      ids.add(Extensions.LargeBlob.EXTENSION_ID);
    }
    if (getUvm()) {
      ids.add(Extensions.Uvm.EXTENSION_ID);
    }
    return Collections.unmodifiableSet(ids);
  }

  public static class RegistrationExtensionInputsBuilder {
    /**
     * Enable or disable the FIDO AppID Exclusion Extension (<code>appidExclude</code>).
     *
     * <p>You usually do not need to call this method explicitly; if {@link RelyingParty#getAppId()}
     * is present, then {@link RelyingParty#startRegistration(StartRegistrationOptions)} will enable
     * this extension automatically.
     *
     * <p>If this is set to empty, then {@link
     * RelyingParty#startRegistration(StartRegistrationOptions)} may overwrite it.
     *
     * @see RelyingParty#startRegistration(StartRegistrationOptions)
     * @see <a
     *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-appid-exclude-extension">§10.2.
     *     FIDO AppID Exclusion Extension (appidExclude)</a>
     */
    public RegistrationExtensionInputsBuilder appidExclude(Optional<AppId> appidExclude) {
      this.appidExclude = appidExclude.orElse(null);
      return this;
    }

    /**
     * Enable the FIDO AppID Exclusion Extension (<code>appidExclude</code>).
     *
     * <p>You usually do not need to call this method explicitly; if {@link RelyingParty#getAppId()}
     * is present, then {@link RelyingParty#startRegistration(StartRegistrationOptions)} will enable
     * this extension automatically.
     *
     * <p>If this is set to null, then {@link
     * RelyingParty#startRegistration(StartRegistrationOptions)} may overwrite it.
     *
     * @see RelyingParty#startRegistration(StartRegistrationOptions)
     * @see <a
     *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-appid-exclude-extension">§10.2.
     *     FIDO AppID Exclusion Extension (appidExclude)</a>
     */
    public RegistrationExtensionInputsBuilder appidExclude(AppId appidExclude) {
      this.appidExclude = appidExclude;
      return this;
    }

    /**
     * Enable the Credential Properties (<code>credProps</code>) Extension.
     *
     * @see <a
     *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-authenticator-credential-properties-extension">§10.4.
     *     Credential Properties Extension (credProps)</a>
     */
    public RegistrationExtensionInputsBuilder credProps() {
      this.credProps = true;
      return this;
    }

    /**
     * Enable or disable the Credential Properties (<code>credProps</code>) Extension.
     *
     * <p>A <code>true</code> argument enables the extension. A <code>false</code> argument disables
     * the extension, and will not be overwritten by {@link
     * RelyingParty#startRegistration(StartRegistrationOptions)}. A null argument disables the
     * extension, and will be overwritten by {@link
     * RelyingParty#startRegistration(StartRegistrationOptions)}.
     *
     * @see RelyingParty#startRegistration(StartRegistrationOptions)
     * @see <a
     *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-authenticator-credential-properties-extension">§10.4.
     *     Credential Properties Extension (credProps)</a>
     */
    public RegistrationExtensionInputsBuilder credProps(Boolean credProps) {
      this.credProps = credProps;
      return this;
    }

    /**
     * Enable the Large blob storage extension (<code>largeBlob</code>).
     *
     * <p>Alias of <code>largeBlob(new Extensions.LargeBlob.LargeBlobRegistrationInput(support))
     * </code>.
     *
     * @param support an {@link
     *     com.yubico.webauthn.data.Extensions.LargeBlob.LargeBlobRegistrationInput.LargeBlobSupport}
     *     value to set as the <code>support</code> attribute of the <code>largeBlob</code>
     *     extension input.
     * @see #largeBlob(Extensions.LargeBlob.LargeBlobRegistrationInput)
     * @see <a
     *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-large-blob-extension">§10.5.
     *     Large blob storage extension (largeBlob)</a>
     */
    public RegistrationExtensionInputsBuilder largeBlob(
        Extensions.LargeBlob.LargeBlobRegistrationInput.LargeBlobSupport support) {
      this.largeBlob = new Extensions.LargeBlob.LargeBlobRegistrationInput(support);
      return this;
    }

    /**
     * Enable the Large blob storage extension (<code>largeBlob</code>).
     *
     * @see #largeBlob(Extensions.LargeBlob.LargeBlobRegistrationInput.LargeBlobSupport)
     * @see <a
     *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-large-blob-extension">§10.5.
     *     Large blob storage extension (largeBlob)</a>
     */
    public RegistrationExtensionInputsBuilder largeBlob(
        Extensions.LargeBlob.LargeBlobRegistrationInput largeBlob) {
      this.largeBlob = largeBlob;
      return this;
    }

    /**
     * Enable the User Verification Method Extension (<code>uvm</code>).
     *
     * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-uvm-extension">§10.3.
     *     User Verification Method Extension (uvm)</a>
     */
    public RegistrationExtensionInputsBuilder uvm() {
      this.uvm = true;
      return this;
    }
    /** For compatibility with {@link Builder}(toBuilder = true) */
    private RegistrationExtensionInputsBuilder uvm(Boolean uvm) {
      this.uvm = uvm;
      return this;
    }
  }
}
