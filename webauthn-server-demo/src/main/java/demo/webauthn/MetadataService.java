package demo.webauthn;

import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.attestation.AttestationTrustSource;
import java.util.Set;
import lombok.NonNull;

public interface MetadataService extends AttestationTrustSource {
  Set<Object> findEntries(@NonNull RegistrationResult registrationResult);
}
