package com.yubico.webauthn.data;

import com.yubico.u2f.attestation.Attestation;
import com.yubico.webauthn.util.BinaryUtil;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;


@Value
@Builder
public class RegistrationResult {

    private PublicKeyCredentialDescriptor keyId;
    private boolean attestationTrusted;
    private AttestationType attestationType;
    private Optional<Attestation> attestationMetadata;
    private byte[] publicKeyCose;
    private List<String> warnings;

    RegistrationResult(
        @NonNull PublicKeyCredentialDescriptor keyId,
        boolean attestationTrusted,
        @NonNull AttestationType attestationType,
        @NonNull Optional<Attestation> attestationMetadata,
        @NonNull byte[] publicKeyCose,
        @NonNull List<String> warnings
    ) {
        this.keyId = keyId;
        this.attestationTrusted = attestationTrusted;
        this.attestationType = attestationType;
        this.attestationMetadata = attestationMetadata;
        this.publicKeyCose = BinaryUtil.copy(publicKeyCose);
        this.warnings = Collections.unmodifiableList(warnings);
    }

}
