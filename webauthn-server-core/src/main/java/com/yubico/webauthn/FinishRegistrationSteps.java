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
import com.yubico.webauthn.attestation.AttestationTrustSource;
import com.yubico.webauthn.attestation.AttestationTrustSource.TrustRootsResult;
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
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXCertPathValidatorResult;
import java.security.cert.PKIXParameters;
import java.security.cert.PKIXReason;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.sql.Date;
import java.time.Clock;
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
  private static final ByteArray ZERO_AAGUID =
      new ByteArray(new byte[] {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0});

  private final PublicKeyCredentialCreationOptions request;
  private final PublicKeyCredential<
          AuthenticatorAttestationResponse, ClientRegistrationExtensionOutputs>
      response;
  private final Optional<ByteArray> callerTokenBindingId;
  private final Set<String> origins;
  private final String rpId;
  private final boolean allowUntrustedAttestation;
  private final Optional<AttestationTrustSource> attestationTrustSource;
  private final CredentialRepository credentialRepository;
  private final Clock clock;

  @Builder.Default private final boolean allowOriginPort = false;
  @Builder.Default private final boolean allowOriginSubdomain = false;
  @Builder.Default private final boolean allowUnrequestedExtensions = false;

  public Step6 begin() {
    return new Step6();
  }

  public RegistrationResult run() {
    return begin().run();
  }

  interface Step<Next extends Step<?>> {
    Next nextStep();

    void validate();

    default Optional<RegistrationResult> result() {
      return Optional.empty();
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

  // Steps 1 through 4 are to create the request and run the client-side part

  // Step 5 is integrated into step 6 here

  @Value
  class Step6 implements Step<Step7> {
    @Override
    public void validate() {
      assure(clientData() != null, "Client data must not be null.");
    }

    @Override
    public Step7 nextStep() {
      return new Step7(clientData());
    }

    public CollectedClientData clientData() {
      return response.getResponse().getClientData();
    }
  }

  @Value
  class Step7 implements Step<Step8> {
    private final CollectedClientData clientData;

    @Override
    public void validate() {
      assure(
          CLIENT_DATA_TYPE.equals(clientData.getType()),
          "The \"type\" in the client data must be exactly \"%s\", was: %s",
          CLIENT_DATA_TYPE,
          clientData.getType());
    }

    @Override
    public Step8 nextStep() {
      return new Step8(clientData);
    }
  }

  @Value
  class Step8 implements Step<Step9> {
    private final CollectedClientData clientData;

    @Override
    public void validate() {
      assure(request.getChallenge().equals(clientData.getChallenge()), "Incorrect challenge.");
    }

    @Override
    public Step9 nextStep() {
      return new Step9(clientData);
    }
  }

  @Value
  class Step9 implements Step<Step10> {
    private final CollectedClientData clientData;

    @Override
    public void validate() {
      final String responseOrigin = clientData.getOrigin();
      assure(
          OriginMatcher.isAllowed(responseOrigin, origins, allowOriginPort, allowOriginSubdomain),
          "Incorrect origin: " + responseOrigin);
    }

    @Override
    public Step10 nextStep() {
      return new Step10(clientData);
    }
  }

  @Value
  class Step10 implements Step<Step11> {
    private final CollectedClientData clientData;

    @Override
    public void validate() {
      TokenBindingValidator.validate(clientData.getTokenBinding(), callerTokenBindingId);
    }

    @Override
    public Step11 nextStep() {
      return new Step11();
    }
  }

  @Value
  class Step11 implements Step<Step12> {
    @Override
    public void validate() {
      assure(clientDataJsonHash().size() == 32, "Failed to compute hash of client data");
    }

    @Override
    public Step12 nextStep() {
      return new Step12(clientDataJsonHash());
    }

    public ByteArray clientDataJsonHash() {
      return Crypto.sha256(response.getResponse().getClientDataJSON());
    }
  }

  @Value
  class Step12 implements Step<Step13> {
    private final ByteArray clientDataJsonHash;

    @Override
    public void validate() {
      assure(attestation() != null, "Malformed attestation object.");
    }

    @Override
    public Step13 nextStep() {
      return new Step13(clientDataJsonHash, attestation());
    }

    public AttestationObject attestation() {
      return response.getResponse().getAttestation();
    }
  }

  @Value
  class Step13 implements Step<Step14> {
    private final ByteArray clientDataJsonHash;
    private final AttestationObject attestation;

    @Override
    public void validate() {
      assure(
          Crypto.sha256(rpId)
              .equals(response.getResponse().getAttestation().getAuthenticatorData().getRpIdHash()),
          "Wrong RP ID hash.");
    }

    @Override
    public Step14 nextStep() {
      return new Step14(clientDataJsonHash, attestation);
    }
  }

  @Value
  class Step14 implements Step<Step15> {
    private final ByteArray clientDataJsonHash;
    private final AttestationObject attestation;

    @Override
    public void validate() {
      assure(
          response.getResponse().getParsedAuthenticatorData().getFlags().UP,
          "User Presence is required.");
    }

    @Override
    public Step15 nextStep() {
      return new Step15(clientDataJsonHash, attestation);
    }
  }

  @Value
  class Step15 implements Step<Step16> {
    private final ByteArray clientDataJsonHash;
    private final AttestationObject attestation;

    @Override
    public void validate() {
      if (request
              .getAuthenticatorSelection()
              .flatMap(AuthenticatorSelectionCriteria::getUserVerification)
              .orElse(UserVerificationRequirement.PREFERRED)
          == UserVerificationRequirement.REQUIRED) {
        assure(
            response.getResponse().getParsedAuthenticatorData().getFlags().UV,
            "User Verification is required.");
      }
    }

    @Override
    public Step16 nextStep() {
      return new Step16(clientDataJsonHash, attestation);
    }
  }

  @Value
  class Step16 implements Step<Step18> {
    private final ByteArray clientDataJsonHash;
    private final AttestationObject attestation;

    @Override
    public void validate() {
      final ByteArray publicKeyCose =
          response
              .getResponse()
              .getAttestation()
              .getAuthenticatorData()
              .getAttestedCredentialData()
              .get()
              .getCredentialPublicKey();
      CBORObject publicKeyCbor = CBORObject.DecodeFromBytes(publicKeyCose.getBytes());
      final int alg = publicKeyCbor.get(CBORObject.FromObject(3)).AsInt32();
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
    public Step18 nextStep() {
      return new Step18(clientDataJsonHash, attestation);
    }
  }

  // Nothing to do for step 17

  @Value
  class Step18 implements Step<Step19> {
    private final ByteArray clientDataJsonHash;
    private final AttestationObject attestation;

    @Override
    public void validate() {}

    @Override
    public Step19 nextStep() {
      return new Step19(clientDataJsonHash, attestation, attestationStatementVerifier());
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
        case "tpm":
          return Optional.of(new TpmAttestationStatementVerifier());
        default:
          return Optional.empty();
      }
    }
  }

  @Value
  class Step19 implements Step<Step20> {
    private final ByteArray clientDataJsonHash;
    private final AttestationObject attestation;
    private final Optional<AttestationStatementVerifier> attestationStatementVerifier;

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
    public Step20 nextStep() {
      return new Step20(attestation, attestationType(), attestationTrustPath());
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
  class Step20 implements Step<Step21> {
    private final AttestationObject attestation;
    private final AttestationType attestationType;
    private final Optional<List<X509Certificate>> attestationTrustPath;

    private final Optional<AttestationTrustSource.TrustRootsResult> trustRoots;

    public Step20(
        AttestationObject attestation,
        AttestationType attestationType,
        Optional<List<X509Certificate>> attestationTrustPath) {
      this.attestation = attestation;
      this.attestationType = attestationType;
      this.attestationTrustPath = attestationTrustPath;
      this.trustRoots = findTrustRoots();
    }

    @Override
    public void validate() {}

    @Override
    public Step21 nextStep() {
      return new Step21(attestation, attestationType, attestationTrustPath, trustRoots);
    }

    private Optional<AttestationTrustSource.TrustRootsResult> findTrustRoots() {
      return attestationTrustSource.flatMap(
          attestationTrustSource ->
              attestationTrustPath.map(
                  atp ->
                      attestationTrustSource.findTrustRoots(
                          atp,
                          Optional.of(
                                  attestation
                                      .getAuthenticatorData()
                                      .getAttestedCredentialData()
                                      .get()
                                      .getAaguid())
                              .filter(aaguid -> !aaguid.equals(ZERO_AAGUID)))));
    }
  }

  @Value
  class Step21 implements Step<Step22> {
    private final AttestationObject attestation;
    private final AttestationType attestationType;
    private final Optional<List<X509Certificate>> attestationTrustPath;
    private final Optional<AttestationTrustSource.TrustRootsResult> trustRoots;

    private final boolean attestationTrusted;

    public Step21(
        AttestationObject attestation,
        AttestationType attestationType,
        Optional<List<X509Certificate>> attestationTrustPath,
        Optional<AttestationTrustSource.TrustRootsResult> trustRoots) {
      this.attestation = attestation;
      this.attestationType = attestationType;
      this.attestationTrustPath = attestationTrustPath;
      this.trustRoots = trustRoots;

      this.attestationTrusted = attestationTrusted();
    }

    @Override
    public void validate() {
      assure(
          allowUntrustedAttestation || attestationTrusted,
          "Failed to derive trust for attestation key.");
    }

    @Override
    public Step22 nextStep() {
      return new Step22(attestationType, attestationTrusted, attestationTrustPath);
    }

    public boolean attestationTrusted() {
      if (attestationTrustPath.isPresent() && attestationTrustSource.isPresent()) {
        try {
          if (!trustRoots.isPresent() || trustRoots.get().getTrustRoots().isEmpty()) {
            return false;

          } else {
            final CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
            final CertPathValidator cpv = CertPathValidator.getInstance("PKIX");
            final CertPath certPath = certFactory.generateCertPath(attestationTrustPath.get());
            final PKIXParameters pathParams =
                new PKIXParameters(
                    trustRoots.get().getTrustRoots().stream()
                        .map(rootCert -> new TrustAnchor(rootCert, null))
                        .collect(Collectors.toSet()));
            pathParams.setDate(Date.from(clock.instant()));
            pathParams.setRevocationEnabled(trustRoots.get().isEnableRevocationChecking());
            pathParams.setPolicyQualifiersRejected(
                !trustRoots.get().getPolicyTreeValidator().isPresent());
            trustRoots.get().getCertStore().ifPresent(pathParams::addCertStore);
            final PKIXCertPathValidatorResult result =
                (PKIXCertPathValidatorResult) cpv.validate(certPath, pathParams);
            return trustRoots
                .get()
                .getPolicyTreeValidator()
                .map(
                    policyNodePredicate -> {
                      if (policyNodePredicate.test(result.getPolicyTree())) {
                        return true;
                      } else {
                        log.info(
                            "Failed to derive trust in attestation statement: Certificate path policy tree does not satisfy policy tree validator. Attestation object: {}",
                            response.getResponse().getAttestationObject());
                        return false;
                      }
                    })
                .orElse(true);
          }

        } catch (CertPathValidatorException e) {
          log.info(
              "Failed to derive trust in attestation statement: {} at cert index {}: {}. Attestation object: {}",
              e.getReason(),
              e.getIndex(),
              e.getMessage(),
              response.getResponse().getAttestationObject());
          if (PKIXReason.INVALID_POLICY.equals(e.getReason())) {
            log.info(
                "You may need to set the policyTreeValidator property on the {} returned by your {}.",
                TrustRootsResult.class.getSimpleName(),
                AttestationTrustSource.class.getSimpleName());
          }
          return false;

        } catch (CertificateException e) {
          log.warn(
              "Failed to build attestation certificate path. Attestation object: {}",
              response.getResponse().getAttestationObject(),
              e);
          return false;

        } catch (NoSuchAlgorithmException e) {
          throw new RuntimeException(
              "Failed to check attestation trust path. A JCA provider is likely missing in the runtime environment.",
              e);

        } catch (InvalidAlgorithmParameterException e) {
          throw new RuntimeException(
              "Failed to initialize attestation trust path validator. This is likely a bug, please file a bug report.",
              e);
        }
      } else {
        return false;
      }
    }
  }

  @Value
  class Step22 implements Step<Finished> {
    private final AttestationType attestationType;
    private final boolean attestationTrusted;
    private final Optional<List<X509Certificate>> attestationTrustPath;

    @Override
    public void validate() {
      assure(
          credentialRepository.lookupAll(response.getId()).isEmpty(),
          "Credential ID is already registered: %s",
          response.getId());
    }

    @Override
    public Finished nextStep() {
      return new Finished(attestationType, attestationTrusted, attestationTrustPath);
    }
  }

  // Step 23 will be performed externally by library user
  // Nothing to do for step 24

  @Value
  class Finished implements Step<Finished> {
    private final AttestationType attestationType;
    private final boolean attestationTrusted;
    private final Optional<List<X509Certificate>> attestationTrustPath;

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
              .aaguid(
                  response
                      .getResponse()
                      .getAttestation()
                      .getAuthenticatorData()
                      .getAttestedCredentialData()
                      .get()
                      .getAaguid())
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
              .attestationTrustPath(attestationTrustPath.orElse(null))
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
