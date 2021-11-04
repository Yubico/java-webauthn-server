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

import static com.yubico.internal.util.ExceptionUtil.assure;
import static com.yubico.internal.util.ExceptionUtil.wrapAndLog;

import COSE.CoseException;
import com.upokecenter.cbor.CBORObject;
import com.yubico.internal.util.CollectionUtil;
import com.yubico.webauthn.attestation.Attestation;
import com.yubico.webauthn.attestation.MetadataService;
import com.yubico.webauthn.data.AttestationObject;
import com.yubico.webauthn.data.AttestationType;
import com.yubico.webauthn.data.AuthenticatorAttestationResponse;
import com.yubico.webauthn.data.AuthenticatorRegistrationExtensionOutputs;
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.ClientRegistrationExtensionOutputs;
import com.yubico.webauthn.data.CollectedClientData;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.UserVerificationRequirement;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.Builder;
import lombok.Value;
import lombok.extern.slf4j.Slf4j;

@Builder
@Slf4j
final class FinishRegistrationSteps {

  private static final String CLIENT_DATA_TYPE = "webauthn.create";

  private final PublicKeyCredentialCreationOptions request;
  private final PublicKeyCredential<
          AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs>
      response;
  private final Optional<ByteArray> callerTokenBindingId;
  private final Set<String> origins;
  private final String rpId;
  private final boolean allowUntrustedAttestation;
  private final Optional<MetadataService> metadataService;
  private final CredentialRepository credentialRepository;

  @Builder.Default private final boolean allowOriginPort = false;
  @Builder.Default private final boolean allowOriginSubdomain = false;
  @Builder.Default private final boolean allowUnrequestedExtensions = false;

  public Step1 begin() {
    return new Step1();
  }

  public RegistrationResult run() {
    return begin().run();
  }

  interface Step<Next extends Step<?>> {
    Next nextStep();

    void validate();

    List<String> getPrevWarnings();

    default Optional<RegistrationResult> result() {
      return Optional.empty();
    }

    default List<String> getWarnings() {
      return Collections.emptyList();
    }

    default List<String> allWarnings() {
      List<String> result = new ArrayList<>(getPrevWarnings().size() + getWarnings().size());
      result.addAll(getPrevWarnings());
      result.addAll(getWarnings());
      return CollectionUtil.immutableList(result);
    }

    default Next next() {
      validate();
      return nextStep();
    }

    default RegistrationResult run() {
      if (result().isPresent()) {
        return result().get();
      } else {
        return next().run();
      }
    }
  }

  @Value
  class Step1 implements Step<Step2> {
    @Override
    public void validate() {}

    @Override
    public Step2 nextStep() {
      return new Step2();
    }

    @Override
    public List<String> getPrevWarnings() {
      return Collections.emptyList();
    }
  }

  @Value
  class Step2 implements Step<Step3> {
    @Override
    public void validate() {
      assure(clientData() != null, "Client data must not be null.");
    }

    @Override
    public Step3 nextStep() {
      return new Step3(clientData());
    }

    @Override
    public List<String> getPrevWarnings() {
      return Collections.emptyList();
    }

    public CollectedClientData clientData() {
      return response.getResponse().getClientData();
    }
  }

  @Value
  class Step3 implements Step<Step4> {
    private final CollectedClientData clientData;

    private List<String> warnings = new ArrayList<>(0);

    @Override
    public void validate() {
      assure(
          CLIENT_DATA_TYPE.equals(clientData.getType()),
          "The \"type\" in the client data must be exactly \"%s\", was: %s",
          CLIENT_DATA_TYPE,
          clientData.getType());
    }

    @Override
    public Step4 nextStep() {
      return new Step4(clientData, allWarnings());
    }

    @Override
    public List<String> getPrevWarnings() {
      return Collections.emptyList();
    }

    @Override
    public List<String> getWarnings() {
      return CollectionUtil.immutableList(warnings);
    }
  }

  @Value
  class Step4 implements Step<Step5> {
    private final CollectedClientData clientData;
    private final List<String> prevWarnings;

    @Override
    public void validate() {
      assure(request.getChallenge().equals(clientData.getChallenge()), "Incorrect challenge.");
    }

    @Override
    public Step5 nextStep() {
      return new Step5(clientData, allWarnings());
    }
  }

  @Value
  class Step5 implements Step<Step6> {
    private final CollectedClientData clientData;
    private final List<String> prevWarnings;

    @Override
    public void validate() {
      final String responseOrigin = clientData.getOrigin();
      assure(
          OriginMatcher.isAllowed(responseOrigin, origins, allowOriginPort, allowOriginSubdomain),
          "Incorrect origin: " + responseOrigin);
    }

    @Override
    public Step6 nextStep() {
      return new Step6(clientData, allWarnings());
    }
  }

  @Value
  class Step6 implements Step<Step7> {
    private final CollectedClientData clientData;
    private final List<String> prevWarnings;

    @Override
    public void validate() {
      TokenBindingValidator.validate(clientData.getTokenBinding(), callerTokenBindingId);
    }

    @Override
    public Step7 nextStep() {
      return new Step7(allWarnings());
    }
  }

  @Value
  class Step7 implements Step<Step8> {
    private final List<String> prevWarnings;

    @Override
    public void validate() {
      assure(clientDataJsonHash().size() == 32, "Failed to compute hash of client data");
    }

    @Override
    public Step8 nextStep() {
      return new Step8(clientDataJsonHash(), allWarnings());
    }

    public ByteArray clientDataJsonHash() {
      return Crypto.sha256(response.getResponse().getClientDataJSON());
    }
  }

  @Value
  class Step8 implements Step<Step9> {
    private final ByteArray clientDataJsonHash;
    private final List<String> prevWarnings;

    @Override
    public void validate() {
      assure(attestation() != null, "Malformed attestation object.");
    }

    @Override
    public Step9 nextStep() {
      return new Step9(clientDataJsonHash, attestation(), allWarnings());
    }

    public AttestationObject attestation() {
      return response.getResponse().getAttestation();
    }
  }

  @Value
  class Step9 implements Step<Step10> {
    private final ByteArray clientDataJsonHash;
    private final AttestationObject attestation;
    private final List<String> prevWarnings;

    @Override
    public void validate() {
      assure(
          Crypto.sha256(rpId)
              .equals(response.getResponse().getAttestation().getAuthenticatorData().getRpIdHash()),
          "Wrong RP ID hash.");
    }

    @Override
    public Step10 nextStep() {
      return new Step10(clientDataJsonHash, attestation, allWarnings());
    }
  }

  @Value
  class Step10 implements Step<Step11> {
    private final ByteArray clientDataJsonHash;
    private final AttestationObject attestation;
    private final List<String> prevWarnings;

    @Override
    public void validate() {
      assure(
          response.getResponse().getParsedAuthenticatorData().getFlags().UP,
          "User Presence is required.");
    }

    @Override
    public Step11 nextStep() {
      return new Step11(clientDataJsonHash, attestation, allWarnings());
    }
  }

  @Value
  class Step11 implements Step<Step12> {
    private final ByteArray clientDataJsonHash;
    private final AttestationObject attestation;
    private final List<String> prevWarnings;

    @Override
    public void validate() {
      if (request
              .getAuthenticatorSelection()
              .map(AuthenticatorSelectionCriteria::getUserVerification)
              .orElse(UserVerificationRequirement.PREFERRED)
          == UserVerificationRequirement.REQUIRED) {
        assure(
            response.getResponse().getParsedAuthenticatorData().getFlags().UV,
            "User Verification is required.");
      }
    }

    @Override
    public Step12 nextStep() {
      return new Step12(clientDataJsonHash, attestation, allWarnings());
    }
  }

  @Value
  class Step12 implements Step<Step13> {
    private final ByteArray clientDataJsonHash;
    private final AttestationObject attestation;
    private final List<String> prevWarnings;

    @Override
    public void validate() {
      if (!allowUnrequestedExtensions) {
        ExtensionsValidation.validate(request.getExtensions(), response);
      }
    }

    @Override
    public List<String> getWarnings() {
      try {
        ExtensionsValidation.validate(request.getExtensions(), response);
        return Collections.emptyList();
      } catch (Exception e) {
        return Collections.singletonList(e.getMessage());
      }
    }

    @Override
    public Step13 nextStep() {
      return new Step13(clientDataJsonHash, attestation, allWarnings());
    }
  }

  @Value
  class Step13 implements Step<Step14> {
    private final ByteArray clientDataJsonHash;
    private final AttestationObject attestation;
    private final List<String> prevWarnings;

    @Override
    public void validate() {}

    @Override
    public Step14 nextStep() {
      return new Step14(
          clientDataJsonHash, attestation, attestationStatementVerifier(), allWarnings());
    }

    public String format() {
      return attestation.getFormat();
    }

    public Optional<AttestationStatementVerifier> attestationStatementVerifier() {
      switch (format()) {
        case "fido-u2f":
          return Optional.of(new FidoU2fAttestationStatementVerifier());
        case "none":
          return Optional.of(new NoneAttestationStatementVerifier());
        case "packed":
          return Optional.of(new PackedAttestationStatementVerifier());
        case "android-safetynet":
          return Optional.of(new AndroidSafetynetAttestationStatementVerifier());
        case "apple":
          return Optional.of(new AppleAttestationStatementVerifier());
        default:
          return Optional.empty();
      }
    }
  }

  @Value
  class Step14 implements Step<Step15> {
    private final ByteArray clientDataJsonHash;
    private final AttestationObject attestation;
    private final Optional<AttestationStatementVerifier> attestationStatementVerifier;
    private final List<String> prevWarnings;

    @Override
    public void validate() {
      attestationStatementVerifier.ifPresent(
          verifier -> {
            assure(
                verifier.verifyAttestationSignature(attestation, clientDataJsonHash),
                "Invalid attestation signature.");
          });

      assure(attestationType() != null, "Failed to determine attestation type");
    }

    @Override
    public Step15 nextStep() {
      return new Step15(attestation, attestationType(), attestationTrustPath(), allWarnings());
    }

    public AttestationType attestationType() {
      try {
        if (attestationStatementVerifier.isPresent()) {
          return attestationStatementVerifier.get().getAttestationType(attestation);
        } else {
          switch (attestation.getFormat()) {
            case "android-key":
              // TODO delete this once android-key attestation verification is implemented
              return AttestationType.BASIC;
            case "tpm":
              // TODO delete this once tpm attestation verification is implemented
              if (attestation.getAttestationStatement().has("x5c")) {
                return AttestationType.ATTESTATION_CA;
              } else {
                return AttestationType.ECDAA;
              }
            default:
              return AttestationType.UNKNOWN;
          }
        }
      } catch (IOException | CoseException | CertificateException e) {
        throw new IllegalArgumentException("Failed to resolve attestation type.", e);
      }
    }

    public Optional<List<X509Certificate>> attestationTrustPath() {
      if (attestationStatementVerifier.isPresent()) {
        AttestationStatementVerifier verifier = attestationStatementVerifier.get();
        if (verifier instanceof X5cAttestationStatementVerifier) {
          try {
            return ((X5cAttestationStatementVerifier) verifier)
                .getAttestationTrustPath(attestation);
          } catch (CertificateException e) {
            throw new IllegalArgumentException("Failed to resolve attestation trust path.", e);
          }
        } else {
          return Optional.empty();
        }
      } else {
        return Optional.empty();
      }
    }
  }

  @Value
  class Step15 implements Step<Step16> {
    private final AttestationObject attestation;
    private final AttestationType attestationType;
    private final Optional<List<X509Certificate>> attestationTrustPath;
    private final List<String> prevWarnings;

    @Override
    public void validate() {}

    @Override
    public Step16 nextStep() {
      return new Step16(
          attestation, attestationType, attestationTrustPath, trustResolver(), allWarnings());
    }

    public Optional<AttestationTrustResolver> trustResolver() {
      switch (attestationType) {
        case NONE:
        case SELF_ATTESTATION:
        case UNKNOWN:
          return Optional.empty();

        case ANONYMIZATION_CA:
        case ATTESTATION_CA:
        case BASIC:
          switch (attestation.getFormat()) {
            case "android-key":
            case "android-safetynet":
            case "apple":
            case "fido-u2f":
            case "packed":
            case "tpm":
              return metadataService.map(KnownX509TrustAnchorsTrustResolver::new);
            default:
              throw new UnsupportedOperationException(
                  String.format(
                      "Attestation type %s is not supported for attestation statement format \"%s\".",
                      attestationType, attestation.getFormat()));
          }

        default:
          throw new UnsupportedOperationException(
              "Attestation type not implemented: " + attestationType);
      }
    }
  }

  @Value
  class Step16 implements Step<Step17> {
    private final AttestationObject attestation;
    private final AttestationType attestationType;
    private final Optional<List<X509Certificate>> attestationTrustPath;
    private final Optional<AttestationTrustResolver> trustResolver;
    private final List<String> prevWarnings;

    @Override
    public void validate() {
      assure(
          trustResolver.isPresent() || allowUntrustedAttestation,
          "Failed to obtain attestation trust anchors.");

      switch (attestationType) {
        case SELF_ATTESTATION:
          assure(allowUntrustedAttestation, "Self attestation is not allowed.");
          break;

        case ANONYMIZATION_CA:
        case ATTESTATION_CA:
        case BASIC:
          assure(
              allowUntrustedAttestation || attestationTrusted(),
              "Failed to derive trust for attestation key.");
          break;

        case NONE:
          assure(allowUntrustedAttestation, "No attestation is not allowed.");
          break;

        case UNKNOWN:
          assure(
              allowUntrustedAttestation, "Unknown attestation statement formats are not allowed.");
          break;

        default:
          throw new UnsupportedOperationException(
              "Attestation type not implemented: " + attestationType);
      }
    }

    @Override
    public Step17 nextStep() {
      return new Step17(
          attestationType, attestationMetadata(), attestationTrusted(), allWarnings());
    }

    public boolean attestationTrusted() {
      switch (attestationType) {
        case NONE:
        case SELF_ATTESTATION:
        case UNKNOWN:
          return false;

        case ANONYMIZATION_CA:
        case ATTESTATION_CA:
        case BASIC:
          return attestationMetadata().filter(Attestation::isTrusted).isPresent();
        default:
          throw new UnsupportedOperationException(
              "Attestation type not implemented: " + attestationType);
      }
    }

    public Optional<Attestation> attestationMetadata() {
      return trustResolver.flatMap(
          tr -> {
            try {
              return Optional.of(
                  tr.resolveTrustAnchor(attestationTrustPath.orElseGet(Collections::emptyList)));
            } catch (CertificateEncodingException e) {
              log.debug("Failed to resolve trust anchor for attestation: {}", attestation, e);
              return Optional.empty();
            }
          });
    }

    @Override
    public List<String> getWarnings() {
      return trustResolver
          .map(
              tr -> {
                try {
                  tr.resolveTrustAnchor(attestationTrustPath.orElseGet(Collections::emptyList));
                  return Collections.<String>emptyList();
                } catch (CertificateEncodingException e) {
                  return Collections.singletonList("Failed to resolve trust anchor: " + e);
                }
              })
          .orElseGet(Collections::emptyList);
    }
  }

  @Value
  class Step17 implements Step<Step18> {
    private final AttestationType attestationType;
    private final Optional<Attestation> attestationMetadata;
    private final boolean attestationTrusted;
    private final List<String> prevWarnings;

    @Override
    public void validate() {
      assure(
          credentialRepository.lookupAll(response.getId()).isEmpty(),
          "Credential ID is already registered: %s",
          response.getId());
    }

    @Override
    public Step18 nextStep() {
      return new Step18(attestationType, attestationMetadata, attestationTrusted, allWarnings());
    }
  }

  @Value
  class Step18 implements Step<Step19> {
    private final AttestationType attestationType;
    private final Optional<Attestation> attestationMetadata;
    private final boolean attestationTrusted;
    private final List<String> prevWarnings;

    @Override
    public void validate() {}

    @Override
    public Step19 nextStep() {
      return new Step19(attestationType, attestationMetadata, attestationTrusted, allWarnings());
    }
  }

  @Value
  class Step19 implements Step<CustomLastStep> {
    private final AttestationType attestationType;
    private final Optional<Attestation> attestationMetadata;
    private final boolean attestationTrusted;
    private final List<String> prevWarnings;

    @Override
    public void validate() {}

    @Override
    public CustomLastStep nextStep() {
      return new CustomLastStep(
          attestationType, attestationMetadata, attestationTrusted, allWarnings());
    }
  }

  /** Steps that aren't yet standardised in a stable edition of the spec */
  @Value
  class CustomLastStep implements Step<Finished> {
    private final AttestationType attestationType;
    private final Optional<Attestation> attestationMetadata;
    private final boolean attestationTrusted;
    private final List<String> prevWarnings;

    @Override
    public void validate() {
      ByteArray publicKeyCose =
          response
              .getResponse()
              .getAttestation()
              .getAuthenticatorData()
              .getAttestedCredentialData()
              .get()
              .getCredentialPublicKey();
      CBORObject publicKeyCbor = CBORObject.DecodeFromBytes(publicKeyCose.getBytes());
      int alg = publicKeyCbor.get(CBORObject.FromObject(3)).AsInt32();
      assure(
          request.getPubKeyCredParams().stream()
              .anyMatch(pkcparam -> pkcparam.getAlg().getId() == alg),
          "Unrequested credential key algorithm: got %d, expected one of: %s",
          alg,
          request.getPubKeyCredParams().stream()
              .map(pkcparam -> pkcparam.getAlg())
              .collect(Collectors.toList()));
      try {
        WebAuthnCodecs.importCosePublicKey(publicKeyCose);
      } catch (CoseException | IOException | InvalidKeySpecException | NoSuchAlgorithmException e) {
        throw wrapAndLog(log, "Failed to parse credential public key", e);
      }
    }

    @Override
    public Finished nextStep() {
      return new Finished(attestationType, attestationMetadata, attestationTrusted, allWarnings());
    }
  }

  @Value
  class Finished implements Step<Finished> {
    private final AttestationType attestationType;
    private final Optional<Attestation> attestationMetadata;
    private final boolean attestationTrusted;
    private final List<String> prevWarnings;

    @Override
    public void validate() {
      /* No-op */
    }

    @Override
    public Finished nextStep() {
      return this;
    }

    @Override
    public Optional<RegistrationResult> result() {
      return Optional.of(
          RegistrationResult.builder()
              .keyId(keyId())
              .attestationTrusted(attestationTrusted)
              .attestationType(attestationType)
              .publicKeyCose(
                  response
                      .getResponse()
                      .getAttestation()
                      .getAuthenticatorData()
                      .getAttestedCredentialData()
                      .get()
                      .getCredentialPublicKey())
              .signatureCount(
                  response.getResponse().getParsedAuthenticatorData().getSignatureCounter())
              .clientExtensionOutputs(response.getClientExtensionResults())
              .authenticatorExtensionOutputs(
                  AuthenticatorRegistrationExtensionOutputs.fromAuthenticatorData(
                          response.getResponse().getParsedAuthenticatorData())
                      .orElse(null))
              .attestationMetadata(attestationMetadata)
              .warnings(allWarnings())
              .build());
    }

    private PublicKeyCredentialDescriptor keyId() {
      return PublicKeyCredentialDescriptor.builder()
          .id(response.getId())
          .type(response.getType())
          .transports(response.getResponse().getTransports())
          .build();
    }
  }
}
