package com.yubico.webauthn.data;

import com.yubico.webauthn.attestation.Attestation;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import lombok.Builder;
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
    private final List<String> warnings;

    @NonNull
    @Builder.Default
    private final Optional<Attestation> attestationMetadata = Optional.empty();

    private RegistrationResult(
        @NonNull PublicKeyCredentialDescriptor keyId,
        boolean attestationTrusted,
        @NonNull AttestationType attestationType,
        @NonNull ByteArray publicKeyCose,
        @NonNull List<String> warnings,
        @NonNull Optional<Attestation> attestationMetadata
    ) {
        this.keyId = keyId;
        this.attestationTrusted = attestationTrusted;
        this.attestationType = attestationType;
        this.publicKeyCose = publicKeyCose;
        this.warnings = Collections.unmodifiableList(warnings);
        this.attestationMetadata = attestationMetadata;
    }

}
