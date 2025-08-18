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
  private final Extensions.CredentialProtection.CredentialProtectionInput credProtect;
  private final Extensions.LargeBlob.LargeBlobRegistrationInput largeBlob;
  private final Extensions.Prf.PrfRegistrationInput prf;
  private final Extensions.Spc.SpcRegistrationInput spc;
  private final Boolean uvm;

  private RegistrationExtensionInputs(
      AppId appidExclude,
      Boolean credProps,
      Extensions.CredentialProtection.CredentialProtectionInput credProtect,
      Extensions.LargeBlob.LargeBlobRegistrationInput largeBlob,
      Extensions.Prf.PrfRegistrationInput prf,
      Extensions.Spc.SpcRegistrationInput spc,
      Boolean uvm) {
    this.appidExclude = appidExclude;
    this.credProps = credProps;
    this.credProtect = credProtect;
    this.largeBlob = largeBlob;
    this.prf = prf;
    this.spc = spc;
    this.uvm = uvm;
  }

  @JsonCreator
  private RegistrationExtensionInputs(
      @JsonProperty("appidExclude") AppId appidExclude,
      @JsonProperty("credProps") Boolean credProps,
      @JsonProperty("credentialProtectionPolicy")
          Extensions.CredentialProtection.CredentialProtectionPolicy credProtectPolicy,
      @JsonProperty("enforceCredentialProtectionPolicy") Boolean enforceCredProtectPolicy,
      @JsonProperty("largeBlob") Extensions.LargeBlob.LargeBlobRegistrationInput largeBlob,
      @JsonProperty("prf") Extensions.Prf.PrfRegistrationInput prf,
      @JsonProperty("spc") Extensions.Spc.SpcRegistrationInput spc,
      @JsonProperty("uvm") Boolean uvm) {
    this(
        appidExclude,
        credProps,
        Optional.ofNullable(credProtectPolicy)
            .map(
                policy -> {
                  return enforceCredProtectPolicy != null && enforceCredProtectPolicy
                      ? Extensions.CredentialProtection.CredentialProtectionInput.require(policy)
                      : Extensions.CredentialProtection.CredentialProtectionInput.prefer(policy);
                })
            .orElse(null),
        largeBlob,
        prf,
        spc,
        uvm);
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
        this.credProtect != null ? this.credProtect : other.credProtect,
        this.largeBlob != null ? this.largeBlob : other.largeBlob,
        this.prf != null ? this.prf : other.prf,
        this.spc != null ? this.spc : other.spc,
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
   * @return The Credential Protection (<code>credProtect</code>) extension input, if set.
   * @since 2.7.0
   * @see
   *     RegistrationExtensionInputsBuilder#credProtect(Extensions.CredentialProtection.CredentialProtectionInput)
   * @see <a
   *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-authenticator-credential-properties-extension">§10.4.
   *     Credential Properties Extension (credProps)</a>
   */
  @JsonIgnore
  public Optional<Extensions.CredentialProtection.CredentialProtectionInput> getCredProtect() {
    return Optional.ofNullable(credProtect);
  }

  /**
   * For JSON serialization, because credProtect does not group all inputs under the "credProtect"
   * key.
   */
  @JsonProperty("credentialProtectionPolicy")
  private Optional<Extensions.CredentialProtection.CredentialProtectionPolicy>
      getCredProtectPolicy() {
    return getCredProtect()
        .map(
            Extensions.CredentialProtection.CredentialProtectionInput
                ::getCredentialProtectionPolicy);
  }

  /**
   * For JSON serialization, because credProtect does not group all inputs under the "credProtect"
   * key.
   */
  @JsonProperty("enforceCredentialProtectionPolicy")
  private Optional<Boolean> getEnforceCredProtectPolicy() {
    return getCredProtect()
        .map(
            Extensions.CredentialProtection.CredentialProtectionInput
                ::isEnforceCredentialProtectionPolicy);
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
   * The input to the Pseudo-random function extension (<code>prf</code>), if any.
   *
   * <p>This extension allows a Relying Party to evaluate outputs from a pseudo-random function
   * (PRF) associated with a credential.
   *
   * @since 2.7.0
   * @see Extensions.Prf.PrfRegistrationInput#enable()
   * @see Extensions.Prf.PrfRegistrationInput#eval(Extensions.Prf.PrfValues)
   * @see <a href="https://www.w3.org/TR/2025/WD-webauthn-3-20250127/#prf-extension">§10.1.4.
   *     Pseudo-random function extension (prf)</a>
   */
  public Optional<Extensions.Prf.PrfRegistrationInput> getPrf() {
    return Optional.ofNullable(prf);
  }

  /**
   * The input to the Secure Payment Confirmation (<code>spc</code>) extension, if any.
   *
   * <p>This extension indicates that a credential is either being created for or used for Secure
   * Payment Confirmation, respectively.
   *
   * @see <a
   *     href="https://www.w3.org/TR/secure-payment-confirmation/#sctn-payment-extension-registration">§5.
   *     Secure Payment Confirmation extension (SPC)</a>
   */
  public Optional<Extensions.Spc.SpcRegistrationInput> getSpc() {
    return Optional.ofNullable(spc);
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
    if (getCredProtect().isPresent()) {
      ids.add(Extensions.CredentialProtection.EXTENSION_ID);
    }
    if (largeBlob != null) {
      ids.add(Extensions.LargeBlob.EXTENSION_ID);
    }
    if (prf != null) {
      ids.add(Extensions.Prf.EXTENSION_ID);
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
     * Enable or disable the Credential Protection (<code>credProtect</code>) extension.
     *
     * @since 2.7.0
     * @see
     *     Extensions.CredentialProtection.CredentialProtectionInput#prefer(Extensions.CredentialProtection.CredentialProtectionPolicy)
     * @see
     *     Extensions.CredentialProtection.CredentialProtectionInput#require(Extensions.CredentialProtection.CredentialProtectionPolicy)
     * @see <a
     *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-credProtect-extension">CTAP2
     *     §12.1. Credential Protection (credProtect)</a>
     */
    public RegistrationExtensionInputsBuilder credProtect(
        Optional<Extensions.CredentialProtection.CredentialProtectionInput> credProtect) {
      this.credProtect = credProtect.orElse(null);
      return this;
    }

    /**
     * Enable the Credential Protection (<code>credProtect</code>) extension.
     *
     * @since 2.7.0
     * @see
     *     Extensions.CredentialProtection.CredentialProtectionInput#prefer(Extensions.CredentialProtection.CredentialProtectionPolicy)
     * @see
     *     Extensions.CredentialProtection.CredentialProtectionInput#require(Extensions.CredentialProtection.CredentialProtectionPolicy)
     * @see <a
     *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-credProtect-extension">CTAP2
     *     §12.1. Credential Protection (credProtect)</a>
     */
    public RegistrationExtensionInputsBuilder credProtect(
        Extensions.CredentialProtection.CredentialProtectionInput credProtect) {
      this.credProtect = credProtect;
      return this;
    }

    /**
     * Enable the Large blob storage extension (<code>largeBlob</code>).
     *
     * <p>Alias of <code>largeBlob(new Extensions.LargeBlob.LargeBlobRegistrationInput(support))
     * </code>.
     *
     * @param support an {@link Extensions.LargeBlob.LargeBlobRegistrationInput.LargeBlobSupport}
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
     * Enable the Pseudo-random function extension (<code>prf</code>).
     *
     * <p>This extension allows a Relying Party to evaluate outputs from a pseudo-random function
     * (PRF) associated with a credential.
     *
     * <p>Use the {@link com.yubico.webauthn.data.Extensions.Prf.PrfRegistrationInput} factory
     * functions to construct the argument:
     *
     * <ul>
     *   <li>Use {@link Extensions.Prf.PrfRegistrationInput#enable()} to request that the credential
     *       be capable of PRF evaluation, but without evaluating the PRF at this time.
     *   <li>Use {@link Extensions.Prf.PrfRegistrationInput#eval(Extensions.Prf.PrfValues)} to
     *       request that the credential be capable of PRF evaluation and immediately evaluate it
     *       for the given inputs. Note that not all authenticators support this, in which case a
     *       follow-up authentication ceremony may be needed in order to evaluate the PRF.
     * </ul>
     *
     * @since 2.7.0
     * @see Extensions.Prf.PrfRegistrationInput#enable()
     * @see Extensions.Prf.PrfRegistrationInput#eval(Extensions.Prf.PrfValues)
     * @see <a href="https://www.w3.org/TR/2025/WD-webauthn-3-20250127/#prf-extension">§10.1.4.
     *     Pseudo-random function extension (prf)</a>
     */
    public RegistrationExtensionInputsBuilder prf(Extensions.Prf.PrfRegistrationInput prf) {
      this.prf = prf;
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
