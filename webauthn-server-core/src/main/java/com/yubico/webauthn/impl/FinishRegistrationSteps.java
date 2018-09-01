package com.yubico.webauthn.impl;

import COSE.CoseException;
import com.yubico.attestation.Attestation;
import com.yubico.attestation.MetadataService;
import com.yubico.util.ByteArray;
import com.yubico.webauthn.AttestationStatementVerifier;
import com.yubico.webauthn.AttestationTrustResolver;
import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.Crypto;
import com.yubico.webauthn.data.AttestationObject;
import com.yubico.webauthn.data.AttestationType;
import com.yubico.webauthn.data.AuthenticatorAttestationResponse;
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria;
import com.yubico.webauthn.data.CollectedClientData;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.RegistrationResult;
import com.yubico.webauthn.data.UserVerificationRequirement;
import com.yubico.webauthn.impl.ExtensionsValidation;
import com.yubico.webauthn.impl.FidoU2fAttestationStatementVerifier;
import com.yubico.webauthn.impl.KnownX509TrustAnchorsTrustResolver;
import com.yubico.webauthn.impl.NoneAttestationStatementVerifier;
import com.yubico.webauthn.impl.PackedAttestationStatementVerifier;
import com.yubico.webauthn.impl.TokenBindingValidator;
import com.yubico.webauthn.impl.X5cAttestationStatementVerifier;
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import lombok.Builder;
import lombok.Value;
import lombok.extern.slf4j.Slf4j;

import static com.yubico.util.ExceptionUtil.assure;
import static com.yubico.webauthn.data.AttestationType.NONE;

@Builder
@Slf4j
public class FinishRegistrationSteps {

    private static final String CLIENT_DATA_TYPE = "webauthn.create";

    private final PublicKeyCredentialCreationOptions request;
    private final PublicKeyCredential<AuthenticatorAttestationResponse> response;
    private final Optional<ByteArray> callerTokenBindingId;
    private final List<String> origins;
    private final String rpId;
    private final Crypto crypto;
    private final Boolean allowUntrustedAttestation;
    private final Optional<MetadataService> metadataService;
    private final CredentialRepository credentialRepository;

    @Builder.Default
    private final Boolean allowUnrequestedExtensions = false;
    @Builder.Default
    private final Boolean allowMissingTokenBinding = false;
    @Builder.Default
    private final Boolean validateTypeAttribute = true;


    public Step1 begin() {
        return new Step1();
    }

    public RegistrationResult run() {
        return begin().run();
    }

    private interface Step<A extends Step<?>> {
        A nextStep();

        void validate();

        List<String> getPrevWarnings();

        default boolean isFinished() {
            return false;
        }

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
            return Collections.unmodifiableList(result);
        }

        default A next() {
            validate();
            return nextStep();
        }

        default RegistrationResult run() {
            if (isFinished()) {
                return result().get();
            } else {
                return next().run();
            }
        }
    }

    @Value
    public class Step1 implements Step<Step2> {
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
    public class Step2 implements Step<Step3> {
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
    public class Step3 implements Step<Step4> {
        private final CollectedClientData clientData;

        private List<String> warnings = new ArrayList<>(0);

        @Override
        public void validate() {
            final String type = clientData.getType();

            if (!CLIENT_DATA_TYPE.equals(type)) {
                final String message = String.format(
                    "The \"type\" in the client data must be exactly \"%s\", was: %s",
                    CLIENT_DATA_TYPE, clientData.getType()
                );

                if (validateTypeAttribute) {
                    throw new IllegalArgumentException(message);
                } else {
                    warnings.add(message);
                }
            }
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
            return Collections.unmodifiableList(warnings);
        }
    }

    @Value
    public class Step4 implements Step<Step5> {
        private final CollectedClientData clientData;
        private final List<String> prevWarnings;

        @Override
        public void validate() {
            assure(
                request.getChallenge().equals(clientData.getChallenge()),
                "Incorrect challenge."
            );
        }

        @Override
        public Step5 nextStep() {
            return new Step5(clientData, allWarnings());
        }
    }

    @Value
    public class Step5 implements Step<Step6> {
        private final CollectedClientData clientData;
        private final List<String> prevWarnings;

        @Override
        public void validate() {
            assure(
                origins.stream().anyMatch(o -> o.equals(clientData.getOrigin())),
                "Incorrect origin: " + clientData.getOrigin()
            );
        }

        @Override
        public Step6 nextStep() {
            return new Step6(clientData, allWarnings());
        }
    }

    @Value
    public class Step6 implements Step<Step7> {
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
    public class Step7 implements Step<Step8> {
        private final List<String> prevWarnings;

        @Override
        public void validate() {
            assure(clientDataJsonHash() != null, "Failed to compute hash of client data");
        }

        @Override
        public Step8 nextStep() {
            return new Step8(clientDataJsonHash(), allWarnings());
        }

        public ByteArray clientDataJsonHash() {
            return new ByteArray(crypto.hash(response.getResponse().getClientDataJSON().getBytes()));
        }
    }

    @Value
    public class Step8 implements Step<Step9> {
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
    public class Step9 implements Step<Step10> {
        private final ByteArray clientDataJsonHash;
        private final AttestationObject attestation;
        private final List<String> prevWarnings;

        @Override
        public void validate() {
            assure(
                new ByteArray(crypto.hash(rpId)).equals(response.getResponse().getAttestation().getAuthenticatorData().getRpIdHash()),
                "Wrong RP ID hash."
            );
        }

        @Override
        public Step10 nextStep() {
            return new Step10(clientDataJsonHash, attestation, allWarnings());
        }
    }

    @Value
    public class Step10 implements Step<Step11> {
        private final ByteArray clientDataJsonHash;
        private final AttestationObject attestation;
        private final List<String> prevWarnings;

        @Override
        public void validate() {
            if (request.getAuthenticatorSelection().map(AuthenticatorSelectionCriteria::getUserVerification).orElse(UserVerificationRequirement.PREFERRED) == UserVerificationRequirement.REQUIRED) {
                assure(response.getResponse().getParsedAuthenticatorData().getFlags().UV, "User Verification is required.");
            }
        }

        @Override
        public Step11 nextStep() {
            return new Step11(clientDataJsonHash, attestation, allWarnings());
        }
    }

    @Value
    public class Step11 implements Step<Step12> {
        private final ByteArray clientDataJsonHash;
        private final AttestationObject attestation;
        private final List<String> prevWarnings;

        @Override
        public void validate() {
            if (request.getAuthenticatorSelection().map(AuthenticatorSelectionCriteria::getUserVerification).orElse(UserVerificationRequirement.PREFERRED) != UserVerificationRequirement.REQUIRED) {
                assure(response.getResponse().getParsedAuthenticatorData().getFlags().UP, "User Presence is required.");
            }
        }

        @Override
        public Step12 nextStep() {
            return new Step12(clientDataJsonHash, attestation, allWarnings());
        }
    }

    @Value
    public class Step12 implements Step<Step13> {
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
    public class Step13 implements Step<Step14> {
        private final ByteArray clientDataJsonHash;
        private final AttestationObject attestation;
        private final List<String> prevWarnings;

        @Override
        public void validate() {
            assure(formatSupported(), "Unsupported attestation statement format: %s", format());
        }

        @Override
        public Step14 nextStep() {
            return new Step14(clientDataJsonHash, attestation, attestationStatementVerifier().get(), allWarnings());
        }

        public String format() {
            return attestation.getFormat();
        }

        public boolean formatSupported() {
            return attestationStatementVerifier().isPresent();
        }

        private Optional<AttestationStatementVerifier> attestationStatementVerifier() {
            switch (format()) {
                case "fido-u2f":
                    return Optional.of(new FidoU2fAttestationStatementVerifier());
                case "none":
                    return Optional.of(new NoneAttestationStatementVerifier());
                case "packed":
                    return Optional.of(new PackedAttestationStatementVerifier());
                default:
                    return Optional.empty();
            }
        }
    }

    @Value
    public class Step14 implements Step<Step15> {
        private final ByteArray clientDataJsonHash;
        private final AttestationObject attestation;
        private final AttestationStatementVerifier attestationStatementVerifier;
        private final List<String> prevWarnings;

        @Override
        public void validate() {
            assure(
                attestationStatementVerifier.verifyAttestationSignature(attestation, clientDataJsonHash),
                "Invalid attestation signature."
            );
        }

        @Override
        public Step15 nextStep() {
            return new Step15(attestation, attestationStatementVerifier, attestationType(), allWarnings());
        }

        public AttestationType attestationType() {
            try {
                return attestationStatementVerifier.getAttestationType(attestation);
            } catch (IOException | CoseException | CertificateException e) {
                throw new IllegalArgumentException("Failed to resolve attestation type.", e);
            }
        }

        public Optional<List<X509Certificate>> attestationTrustPath() {
            if (attestationStatementVerifier instanceof X5cAttestationStatementVerifier) {
                try {
                    return ((X5cAttestationStatementVerifier) attestationStatementVerifier).getAttestationTrustPath(attestation);
                } catch (CertificateException e) {
                    throw new IllegalArgumentException("Failed to resolve attestation trust path.", e);
                }
            } else {
                return Optional.empty();
            }
        }
    }

    @Value
    public class Step15 implements Step<Step16> {
        private final AttestationObject attestation;
        private final AttestationStatementVerifier attestationStatementVerifier;
        private final AttestationType attestationType;
        private final List<String> prevWarnings;

        @Override
        public void validate() {
            assure(
                attestationType == AttestationType.SELF_ATTESTATION || attestationType == NONE || trustResolver().isPresent(),
                "Failed to obtain attestation trust anchors."
            );
        }

        @Override
        public Step16 nextStep() {
            return new Step16(attestation, attestationType, trustResolver(), allWarnings());
        }

        public Optional<AttestationTrustResolver> trustResolver() {
            switch (attestationType) {
                case SELF_ATTESTATION:
                    return Optional.empty();

                case BASIC:
                    switch (attestation.getFormat()) {
                        case "fido-u2f":
                        case "packed":
                            try {
                                return Optional.of(new KnownX509TrustAnchorsTrustResolver(metadataService.get()));
                            } catch (Exception e) {
                                return Optional.empty();
                            }
                        default:
                            throw new UnsupportedOperationException(String.format(
                                "Attestation type %s is not supported for attestation statement format \"%s\".",
                                attestationType, attestation.getFormat()
                            ));
                    }

                case NONE:
                    return Optional.empty();

                default:
                    throw new UnsupportedOperationException("Attestation type not implemented: " + attestationType);
            }
        }
    }

    @Value
    public class Step16 implements Step<Step17> {
        private final AttestationObject attestation;
        private final AttestationType attestationType;
        private final Optional<AttestationTrustResolver> trustResolver;
        private final List<String> prevWarnings;

        @Override
        public void validate() {
            switch (attestationType) {
                case SELF_ATTESTATION:
                    assure(allowUntrustedAttestation, "Self attestation is not allowed.");
                    break;

                case BASIC:
                    assure(allowUntrustedAttestation || attestationTrusted(), "Failed to derive trust for attestation key.");
                    break;

                case NONE:
                    assure(allowUntrustedAttestation, "No attestation is not allowed.");
                    break;

                default:
                    throw new UnsupportedOperationException("Attestation type not implemented: " + attestationType);
            }
        }

        @Override
        public Step17 nextStep() {
            return new Step17(attestationType, attestationMetadata(), attestationTrusted(), allWarnings());
        }

        public boolean attestationTrusted() {
            switch (attestationType) {
                case SELF_ATTESTATION:
                case NONE:
                    return false;

                case BASIC:
                    return attestationMetadata().filter(Attestation::isTrusted).isPresent();
                default:
                    throw new UnsupportedOperationException("Attestation type not implemented: " + attestationType);
            }
        }

        public Optional<Attestation> attestationMetadata() {
            return trustResolver.flatMap(tr -> tr.resolveTrustAnchor(attestation));
        }
    }

    @Value
    public class Step17 implements Step<Step18> {
        private final AttestationType attestationType;
        private final Optional<Attestation> attestationMetadata;
        private final boolean attestationTrusted;
        private final List<String> prevWarnings;

        @Override
        public void validate() {
            assure(credentialRepository.lookupAll(response.getId()).isEmpty(), "Credential ID is already registered: %s", response.getId());
        }

        @Override
        public Step18 nextStep() {
            return new Step18(attestationType, attestationMetadata, attestationTrusted, allWarnings());
        }
    }

    @Value
    public class Step18 implements Step<Step19> {
        private final AttestationType attestationType;
        private final Optional<Attestation> attestationMetadata;
        private final boolean attestationTrusted;
        private final List<String> prevWarnings;

        @Override
        public void validate() {
        }

        @Override
        public Step19 nextStep() {
            return new Step19(attestationType, attestationMetadata, attestationTrusted, allWarnings());
        }
    }

    @Value
    public class Step19 implements Step<Finished> {
        private final AttestationType attestationType;
        private final Optional<Attestation> attestationMetadata;
        private final boolean attestationTrusted;
        private final List<String> prevWarnings;

        @Override
        public void validate() {
        }

        @Override
        public Finished nextStep() {
            return new Finished(attestationType, attestationMetadata, attestationTrusted, allWarnings());
        }
    }

    @Value
    public class Finished implements Step<Finished> {
        private final AttestationType attestationType;
        private final Optional<Attestation> attestationMetadata;
        private final boolean attestationTrusted;
        private final List<String> prevWarnings;


        @Override
        public void validate() { /* No-op */ }

        @Override
        public boolean isFinished() {
            return true;
        }

        @Override
        public Finished nextStep() {
            return this;
        }

        @Override
        public Optional<RegistrationResult> result() {
            return Optional.of(RegistrationResult.builder()
                .keyId(keyId())
                .attestationTrusted(attestationTrusted)
                .attestationType(attestationType)
                .attestationMetadata(attestationMetadata)
                .publicKeyCose(response.getResponse().getAttestation().getAuthenticatorData().getAttestationData().get().getCredentialPublicKey())
                .warnings(allWarnings())
                .build()
            );
        }

        private PublicKeyCredentialDescriptor keyId() {
            return PublicKeyCredentialDescriptor.builder()
                .type(response.getType())
                .id(response.getId())
                .build();
        }
    }

}
