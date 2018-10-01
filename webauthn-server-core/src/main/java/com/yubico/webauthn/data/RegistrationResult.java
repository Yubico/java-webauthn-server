package com.yubico.webauthn.data;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.yubico.webauthn.attestation.Attestation;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import lombok.Builder;
import lombok.Builder.Default;
import lombok.NonNull;
import lombok.Value;


@Value
@Builder
public class RegistrationResult {

    @NonNull
    private final PublicKeyCredentialDescriptor keyId;

    private final boolean attestationTrusted;

    @NonNull
    private final AttestationType attestationType;

    @NonNull
    private final ByteArray publicKeyCose;

    @NonNull
    @Builder.Default
    private final List<String> warnings = Collections.emptyList();

    @NonNull
    @Builder.Default
    private final Optional<Attestation> attestationMetadata = Optional.empty();

    @JsonCreator
    private RegistrationResult(
        @NonNull @JsonProperty("keyId") PublicKeyCredentialDescriptor keyId,
        @JsonProperty("attestationTrusted") boolean attestationTrusted,
        @NonNull @JsonProperty("attestationType") AttestationType attestationType,
        @NonNull @JsonProperty("publicKeyCose") ByteArray publicKeyCose,
        @NonNull @JsonProperty("warnings") List<String> warnings,
        @NonNull @JsonProperty("attestationMetadata") Optional<Attestation> attestationMetadata
    ) {
        this.keyId = keyId;
        this.attestationTrusted = attestationTrusted;
        this.attestationType = attestationType;
        this.publicKeyCose = publicKeyCose;
        this.warnings = Collections.unmodifiableList(warnings);
        this.attestationMetadata = attestationMetadata;
    }

}
