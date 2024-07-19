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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.yubico.internal.util.CertificateParser;
import com.yubico.webauthn.RelyingParty.RelyingPartyBuilder;
import com.yubico.webauthn.attestation.AttestationTrustSource;
import com.yubico.webauthn.data.AttestationType;
import com.yubico.webauthn.data.AuthenticatorAttachment;
import com.yubico.webauthn.data.AuthenticatorAttestationResponse;
import com.yubico.webauthn.data.AuthenticatorData;
import com.yubico.webauthn.data.AuthenticatorDataFlags;
import com.yubico.webauthn.data.AuthenticatorRegistrationExtensionOutputs;
import com.yubico.webauthn.data.AuthenticatorResponse;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.ClientRegistrationExtensionOutputs;
import com.yubico.webauthn.data.Extensions;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;
import lombok.AccessLevel;
import lombok.Getter;
import lombok.NonNull;
import lombok.Value;

/** The result of a call to {@link RelyingParty#finishRegistration(FinishRegistrationOptions)}. */
@Value
public class RegistrationResult {

  @JsonProperty
  @Getter(AccessLevel.NONE)
  private final PublicKeyCredential<
          AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs>
      credential;

  /**
   * <code>true</code> if and only if the attestation signature was successfully linked to a trusted
   * attestation root.
   *
   * <p>This will always be <code>false</code> unless the {@link
   * RelyingPartyBuilder#attestationTrustSource(AttestationTrustSource) attestationTrustSource}
   * setting was configured on the {@link RelyingParty} instance.
   *
   * <p>You can ignore this if authenticator attestation is not relevant to your application.
   */
  private final boolean attestationTrusted;

  /**
   * The <a
   * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-attestation-types">attestation
   * type</a> that was used for the created credential.
   *
   * <p>You can ignore this if authenticator attestation is not relevant to your application.
   *
   * @see <a
   *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-attestation-types">§6.4.3.
   *     Attestation Types</a>
   */
  @NonNull private final AttestationType attestationType;

  // JavaDoc on getter
  private final List<X509Certificate> attestationTrustPath;

  RegistrationResult(
      PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs>
          credential,
      boolean attestationTrusted,
      @NonNull AttestationType attestationType,
      Optional<List<X509Certificate>> attestationTrustPath) {
    this.credential = credential;
    this.attestationTrusted = attestationTrusted;
    this.attestationType = attestationType;
    this.attestationTrustPath = attestationTrustPath.orElse(null);
  }

  @JsonCreator
  private static RegistrationResult fromJson(
      @NonNull @JsonProperty("credential")
          PublicKeyCredential<AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs>
              credential,
      @JsonProperty("attestationTrusted") boolean attestationTrusted,
      @NonNull @JsonProperty("attestationType") AttestationType attestationType,
      @NonNull @JsonProperty("attestationTrustPath") Optional<List<String>> attestationTrustPath) {
    return new RegistrationResult(
        credential,
        attestationTrusted,
        attestationType,
        attestationTrustPath.map(
            atp ->
                atp.stream()
                    .map(
                        pem -> {
                          try {
                            return CertificateParser.parsePem(pem);
                          } catch (CertificateException e) {
                            throw new RuntimeException(e);
                          }
                        })
                    .collect(Collectors.toList())));
  }

  /**
   * Check whether the <a href="https://www.w3.org/TR/webauthn/#user-verification">user
   * verification</a> as performed during the registration ceremony.
   *
   * <p>This flag is also available via <code>
   * {@link PublicKeyCredential}.{@link PublicKeyCredential#getResponse() getResponse()}.{@link AuthenticatorResponse#getParsedAuthenticatorData() getParsedAuthenticatorData()}.{@link AuthenticatorData#getFlags() getFlags()}.{@link AuthenticatorDataFlags#UV UV}
   * </code>.
   *
   * @return <code>true</code> if and only if the authenticator claims to have performed user
   *     verification during the registration ceremony.
   * @see <a href="https://www.w3.org/TR/webauthn/#user-verification">User Verification</a>
   * @see <a href="https://w3c.github.io/webauthn/#authdata-flags-uv">UV flag in §6.1. Authenticator
   *     Data</a>
   */
  @JsonIgnore
  public boolean isUserVerified() {
    return credential.getResponse().getParsedAuthenticatorData().getFlags().UV;
  }

  /**
   * Check whether the created credential is <a
   * href="https://w3c.github.io/webauthn/#backup-eligible">backup eligible</a>, using the <a
   * href="https://w3c.github.io/webauthn/#authdata-flags-be">BE flag</a> in the authenticator data.
   *
   * <p>You SHOULD store this value in your representation of a {@link RegisteredCredential}. {@link
   * CredentialRepository} implementations SHOULD set this value as the {@link
   * RegisteredCredential.RegisteredCredentialBuilder#backupEligible(Boolean)
   * backupEligible(Boolean)} value when reconstructing that {@link RegisteredCredential}.
   *
   * @return <code>true</code> if and only if the created credential is backup eligible. NOTE that
   *     this is only a hint and not a guarantee, unless backed by a trusted authenticator
   *     attestation.
   * @see <a href="https://w3c.github.io/webauthn/#backup-eligible">Backup Eligible in §4.
   *     Terminology</a>
   * @see <a href="https://w3c.github.io/webauthn/#authdata-flags-be">BE flag in §6.1. Authenticator
   *     Data</a>
   * @deprecated EXPERIMENTAL: This feature is from a not yet mature standard; it could change as
   *     the standard matures.
   */
  @Deprecated
  @JsonIgnore
  public boolean isBackupEligible() {
    return credential.getResponse().getParsedAuthenticatorData().getFlags().BE;
  }

  /**
   * Get the current <a href="https://w3c.github.io/webauthn/#backup-state">backup state</a> of the
   * created credential, using the <a href="https://w3c.github.io/webauthn/#authdata-flags-bs">BS
   * flag</a> in the authenticator data.
   *
   * <p>You SHOULD store this value in your representation of a {@link RegisteredCredential}. {@link
   * CredentialRepository} implementations SHOULD set this value as the {@link
   * RegisteredCredential.RegisteredCredentialBuilder#backupState(Boolean) backupState(Boolean)}
   * value when reconstructing that {@link RegisteredCredential}.
   *
   * @return <code>true</code> if and only if the created credential is believed to currently be
   *     backed up. NOTE that this is only a hint and not a guarantee, unless backed by a trusted
   *     authenticator attestation.
   * @see <a href="https://w3c.github.io/webauthn/#backup-state">Backup State in §4. Terminology</a>
   * @see <a href="https://w3c.github.io/webauthn/#authdata-flags-bs">BS flag in §6.1. Authenticator
   *     Data</a>
   * @deprecated EXPERIMENTAL: This feature is from a not yet mature standard; it could change as
   *     the standard matures.
   */
  @Deprecated
  @JsonIgnore
  public boolean isBackedUp() {
    return credential.getResponse().getParsedAuthenticatorData().getFlags().BS;
  }

  /**
   * The <a href="https://w3c.github.io/webauthn/#authenticator-attachment-modality">authenticator
   * attachment modality</a> in effect at the time the credential was created.
   *
   * @see PublicKeyCredential#getAuthenticatorAttachment()
   * @deprecated EXPERIMENTAL: This feature is from a not yet mature standard; it could change as
   *     the standard matures.
   */
  @Deprecated
  @JsonIgnore
  public Optional<AuthenticatorAttachment> getAuthenticatorAttachment() {
    return credential.getAuthenticatorAttachment();
  }

  /**
   * The signature count returned with the created credential.
   *
   * <p>This is used in {@link RelyingParty#finishAssertion(FinishAssertionOptions)} to verify the
   * validity of future signature counter values.
   *
   * @see RegisteredCredential#getSignatureCount()
   */
  @JsonIgnore
  public long getSignatureCount() {
    return credential.getResponse().getParsedAuthenticatorData().getSignatureCounter();
  }

  /**
   * The <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#credential-id">credential
   * ID</a> and <a
   * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#dom-publickeycredentialdescriptor-transports">transports</a>
   * of the created credential.
   *
   * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#credential-id">Credential
   *     ID</a>
   * @see <a
   *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#dictionary-credential-descriptor">5.8.3.
   *     Credential Descriptor (dictionary PublicKeyCredentialDescriptor)</a>
   * @see PublicKeyCredential#getId()
   */
  @JsonIgnore
  public PublicKeyCredentialDescriptor getKeyId() {
    return PublicKeyCredentialDescriptor.builder()
        .id(credential.getId())
        .type(credential.getType())
        .transports(credential.getResponse().getTransports())
        .build();
  }

  /**
   * The <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#aaguid"><code>aaguid</code>
   * </a> reported in the <a
   * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-authenticator-data">of the
   * created credential.</a>
   *
   * <p>This MAY be an AAGUID consisting of only zeroes.
   */
  @JsonIgnore
  public ByteArray getAaguid() {
    return credential
        .getResponse()
        .getAttestation()
        .getAuthenticatorData()
        .getAttestedCredentialData()
        .get()
        .getAaguid();
  }

  /**
   * The public key of the created credential.
   *
   * <p>This is used in {@link RelyingParty#finishAssertion(FinishAssertionOptions)} to verify the
   * authentication signatures.
   *
   * @see RegisteredCredential#getPublicKeyCose()
   */
  @JsonIgnore
  public ByteArray getPublicKeyCose() {
    return credential
        .getResponse()
        .getAttestation()
        .getAuthenticatorData()
        .getAttestedCredentialData()
        .get()
        .getCredentialPublicKey();
  }

  /**
   * The public key of the created credential, parsed as a {@link PublicKey} object.
   *
   * @see #getPublicKeyCose()
   * @see RegisteredCredential#getParsedPublicKey()
   */
  @NonNull
  @JsonIgnore
  public PublicKey getParsedPublicKey()
      throws InvalidKeySpecException, NoSuchAlgorithmException, IOException {
    return WebAuthnCodecs.importCosePublicKey(getPublicKeyCose());
  }

  /**
   * The <a
   * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#client-extension-output">client
   * extension outputs</a>, if any.
   *
   * <p>This is present if and only if at least one extension output is present in the return value.
   *
   * @see <a
   *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-client-extension-processing">§9.4.
   *     Client Extension Processing</a>
   * @see ClientRegistrationExtensionOutputs
   * @see #getAuthenticatorExtensionOutputs() ()
   */
  @JsonIgnore
  public Optional<ClientRegistrationExtensionOutputs> getClientExtensionOutputs() {
    return Optional.ofNullable(credential.getClientExtensionResults())
        .filter(ceo -> !ceo.getExtensionIds().isEmpty());
  }

  /**
   * The <a
   * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#authenticator-extension-output">authenticator
   * extension outputs</a>, if any.
   *
   * <p>This is present if and only if at least one extension output is present in the return value.
   *
   * @see <a
   *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-authenticator-extension-processing">§9.5.
   *     Authenticator Extension Processing</a>
   * @see AuthenticatorRegistrationExtensionOutputs
   * @see #getClientExtensionOutputs()
   */
  @JsonIgnore
  public Optional<AuthenticatorRegistrationExtensionOutputs> getAuthenticatorExtensionOutputs() {
    return AuthenticatorRegistrationExtensionOutputs.fromAuthenticatorData(
        credential.getResponse().getParsedAuthenticatorData());
  }

  /**
   * Try to determine whether the created credential is a <a
   * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#discoverable-credential">discoverable
   * credential</a>, also called a <i>passkey</i>, using the output from the <a
   * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#sctn-authenticator-credential-properties-extension">
   * <code>credProps</code></a> extension.
   *
   * @return A present <code>true</code> if the created credential is a passkey (discoverable). A
   *     present <code>
   *     false</code> if the created credential is not a passkey. An empty value if it is not known
   *     whether the created credential is a passkey.
   * @see <a
   *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#dom-credentialpropertiesoutput-rk">§10.4.
   *     Credential Properties Extension (credProps), "rk" output</a>
   * @see <a
   *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#discoverable-credential">Discoverable
   *     Credential</a>
   * @see <a href="https://passkeys.dev/docs/reference/terms/#passkey">Passkey</a> in <a
   *     href="https://passkeys.dev">passkeys.dev</a> reference
   */
  @JsonIgnore
  public Optional<Boolean> isDiscoverable() {
    return getClientExtensionOutputs()
        .flatMap(outputs -> outputs.getCredProps())
        .flatMap(credProps -> credProps.getRk());
  }

  /**
   * Retrieve a suitable nickname for this credential, if one is available.
   *
   * <p>This returns the <code>authenticatorDisplayName</code> output from the <a
   * href="https://w3c.github.io/webauthn/#sctn-authenticator-credential-properties-extension">
   * <code>credProps</code></a> extension.
   *
   * @return A user-chosen or vendor-default display name for the credential, if available.
   *     Otherwise empty.
   * @see <a
   *     href="https://w3c.github.io/webauthn/#dom-credentialpropertiesoutput-authenticatordisplayname">
   *     <code>authenticatorDisplayName</code> in §10.1.3. Credential Properties Extension
   *     (credProps)</a>
   * @see AssertionResult#getAuthenticatorDisplayName()
   * @see AssertionResultV2#getAuthenticatorDisplayName()
   * @see Extensions.CredentialProperties.CredentialPropertiesOutput#getAuthenticatorDisplayName()
   * @deprecated EXPERIMENTAL: This feature is from a not yet mature standard; it could change as
   *     the standard matures.
   */
  @JsonIgnore
  @Deprecated
  public Optional<String> getAuthenticatorDisplayName() {
    return getClientExtensionOutputs()
        .flatMap(outputs -> outputs.getCredProps())
        .flatMap(credProps -> credProps.getAuthenticatorDisplayName());
  }

  /**
   * The <a
   * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#attestation-trust-path">attestation
   * trust path</a> for the created credential, if any.
   *
   * <p>If present, this may be useful for looking up attestation metadata from external sources.
   * The attestation trust path has been successfully verified as trusted if and only if {@link
   * #isAttestationTrusted()} is <code>true</code>.
   *
   * <p>You can ignore this if authenticator attestation is not relevant to your application.
   *
   * @see <a
   *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#attestation-trust-path">Attestation
   *     trust path</a>
   */
  @JsonIgnore
  public Optional<List<X509Certificate>> getAttestationTrustPath() {
    return Optional.ofNullable(attestationTrustPath);
  }

  @JsonProperty("attestationTrustPath")
  private Optional<List<String>> getAttestationTrustPathJson() {
    return getAttestationTrustPath()
        .map(
            x5c ->
                x5c.stream()
                    .map(
                        cert -> {
                          try {
                            return new ByteArray(cert.getEncoded()).getBase64();
                          } catch (CertificateEncodingException e) {
                            throw new RuntimeException(e);
                          }
                        })
                    .collect(Collectors.toList()));
  }
}
