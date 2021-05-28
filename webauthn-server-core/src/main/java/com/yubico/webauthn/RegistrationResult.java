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
import com.fasterxml.jackson.annotation.JsonProperty;
import com.yubico.internal.util.CollectionUtil;
import com.yubico.webauthn.attestation.Attestation;
import com.yubico.webauthn.data.AttestationType;
import com.yubico.webauthn.data.AuthenticatorTransport;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.PublicKeyCredentialRequestOptions;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.SortedSet;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;

/** The result of a call to {@link RelyingParty#finishRegistration(FinishRegistrationOptions)}. */
@Value
@Builder(toBuilder = true)
public class RegistrationResult {

  /**
   * The <a href="https://www.w3.org/TR/2019/PR-webauthn-20190117/#credential-id">credential ID</a>
   * of the created credential.
   *
   * @see <a href="https://www.w3.org/TR/2019/PR-webauthn-20190117/#credential-id">Credential ID</a>
   * @see PublicKeyCredential#getId()
   */
  @NonNull private final PublicKeyCredentialDescriptor keyId;

  /**
   * <code>true</code> if and only if the attestation signature was successfully linked to a trusted
   * attestation root.
   *
   * <p>You can ignore this if authenticator attestation is not relevant to your application.
   */
  private final boolean attestationTrusted;

  /**
   * The attestation type <a
   * href="https://www.w3.org/TR/2019/PR-webauthn-20190117/#sctn-attestation-types">§6.4.3.
   * Attestation Types</a> that was used for the created credential.
   *
   * <p>You can ignore this if authenticator attestation is not relevant to your application.
   *
   * @see <a href="https://www.w3.org/TR/2019/PR-webauthn-20190117/#sctn-attestation-types">§6.4.3.
   *     Attestation Types</a>
   */
  @NonNull private final AttestationType attestationType;

  /**
   * The public key of the created credential.
   *
   * <p>This is used in {@link RelyingParty#finishAssertion(FinishAssertionOptions)} to verify the
   * authentication signatures.
   *
   * @see RegisteredCredential#getPublicKeyCose()
   */
  @NonNull private final ByteArray publicKeyCose;

  /**
   * The signature count returned with the created credential.
   *
   * <p>This is used in {@link RelyingParty#finishAssertion(FinishAssertionOptions)} to verify the
   * validity of future signature counter values.
   *
   * @see RegisteredCredential#getSignatureCount() ()
   */
  private final long signatureCount;

  /** Zero or more human-readable messages about non-critical issues. */
  @NonNull @Builder.Default private final List<String> warnings = Collections.emptyList();

  /**
   * Additional information about the authenticator, identified based on the attestation
   * certificate.
   *
   * <p>This will be absent unless you set a {@link
   * com.yubico.webauthn.RelyingParty.RelyingPartyBuilder#metadataService(Optional) metadataService}
   * in {@link RelyingParty}.
   *
   * @see <a href="https://www.w3.org/TR/2019/PR-webauthn-20190117/#sctn-attestation">§6.4.
   *     Attestation</a>
   * @see com.yubico.webauthn.RelyingParty.RelyingPartyBuilder#metadataService(Optional)
   */
  private final Attestation attestationMetadata;

  /**
   * The transports returned with the created credential.
   *
   * <p>This is used in {@link RelyingParty#startAssertion(StartAssertionOptions)} to set the {@link
   * PublicKeyCredentialDescriptor#getTransports() transports} members of {@link
   * PublicKeyCredentialRequestOptions#getAllowCredentials() allowCredentials}.
   *
   * @see RegisteredCredential#getTransports()
   */
  @NonNull private final SortedSet<AuthenticatorTransport> transports;

  @JsonCreator
  private RegistrationResult(
      @NonNull @JsonProperty("keyId") PublicKeyCredentialDescriptor keyId,
      @JsonProperty("attestationTrusted") boolean attestationTrusted,
      @NonNull @JsonProperty("attestationType") AttestationType attestationType,
      @NonNull @JsonProperty("publicKeyCose") ByteArray publicKeyCose,
      @JsonProperty("signatureCount") Long signatureCount,
      @NonNull @JsonProperty("warnings") List<String> warnings,
      @JsonProperty("attestationMetadata") Attestation attestationMetadata,
      @JsonProperty("transports") Set<AuthenticatorTransport> transports) {
    this.keyId = keyId;
    this.attestationTrusted = attestationTrusted;
    this.attestationType = attestationType;
    this.publicKeyCose = publicKeyCose;
    this.signatureCount = signatureCount == null ? 0 : signatureCount;
    this.transports =
        transports == null
            ? Collections.emptySortedSet()
            : CollectionUtil.immutableSortedSet(transports);
    this.warnings = CollectionUtil.immutableList(warnings);
    this.attestationMetadata = attestationMetadata;
  }

  public Optional<Attestation> getAttestationMetadata() {
    return Optional.ofNullable(attestationMetadata);
  }

  static RegistrationResultBuilder.MandatoryStages builder() {
    return new RegistrationResultBuilder.MandatoryStages();
  }

  static class RegistrationResultBuilder {
    static class MandatoryStages {
      private RegistrationResultBuilder builder = new RegistrationResultBuilder();

      Step2 keyId(PublicKeyCredentialDescriptor keyId) {
        builder.keyId(keyId);
        return new Step2();
      }

      class Step2 {
        Step3 attestationTrusted(boolean attestationTrusted) {
          builder.attestationTrusted(attestationTrusted);
          return new Step3();
        }
      }

      class Step3 {
        Step4 attestationType(AttestationType attestationType) {
          builder.attestationType(attestationType);
          return new Step4();
        }
      }

      class Step4 {
        RegistrationResultBuilder publicKeyCose(ByteArray publicKeyCose) {
          return builder.publicKeyCose(publicKeyCose);
        }
      }

      class Step5 {
        RegistrationResultBuilder signatureCount(long signatureCount) {
          return builder.signatureCount(signatureCount);
        }
      }
    }

    RegistrationResultBuilder attestationMetadata(
        @NonNull Optional<Attestation> attestationMetadata) {
      this.attestationMetadata = attestationMetadata.orElse(null);
      return this;
    }

    /*
     * Workaround, see: https://github.com/rzwitserloot/lombok/issues/2623#issuecomment-714816001
     * Consider reverting this workaround if Lombok fixes that issue.
     */
    private RegistrationResultBuilder attestationMetadata(Attestation attestationMetadata) {
      return this.attestationMetadata(Optional.ofNullable(attestationMetadata));
    }
  }
}
