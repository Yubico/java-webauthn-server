package demo.webauthn;

import com.yubico.fido.metadata.FidoMetadataService;
import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.data.ByteArray;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import lombok.AllArgsConstructor;
import lombok.NonNull;

@AllArgsConstructor
public class FidoMetadataServiceAdapter implements MetadataService {
  private final FidoMetadataService fido;

  @Override
  public TrustRootsResult findTrustRoots(
      List<X509Certificate> attestationCertificateChain, Optional<ByteArray> aaguid) {
    return fido.findTrustRoots(attestationCertificateChain, aaguid);
  }

  @Override
  public Set<Object> findEntries(@NonNull RegistrationResult registrationResult) {
    return fido.findEntries(registrationResult).stream()
        .map(metadataBLOBPayloadEntry -> (Object) metadataBLOBPayloadEntry)
        .collect(Collectors.toSet());
  }
}
