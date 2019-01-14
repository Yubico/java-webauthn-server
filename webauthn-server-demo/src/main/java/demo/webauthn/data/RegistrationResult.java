package demo.webauthn.data;

import com.yubico.webauthn.attestation.Attestation;
import com.yubico.webauthn.data.AttestationType;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
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
    @Builder.Default
    private final List<String> warnings = Collections.emptyList();

    @NonNull
    @Builder.Default
    private final Optional<Attestation> attestationMetadata = Optional.empty();

    public static RegistrationResult fromLibraryType(com.yubico.webauthn.RegistrationResult result) {
        return builder()
            .keyId(result.getKeyId())
            .attestationTrusted(result.isAttestationTrusted())
            .attestationType(result.getAttestationType())
            .publicKeyCose(result.getPublicKeyCose())
            .warnings(result.getWarnings())
            .attestationMetadata(result.getAttestationMetadata())
            .build();
    }

}
