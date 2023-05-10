package demo.webauthn;

import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.attestation.AttestationTrustSource;
import com.yubico.webauthn.data.ByteArray;
import java.security.cert.X509Certificate;
import java.util.*;
import lombok.NonNull;

/**
 * Combines several attestation metadata sources into one, which delegates to each sub-service in
 * order until one returns a non-empty result.
 */
public class CompositeMetadataService implements AttestationTrustSource, MetadataService {

  private final List<MetadataService> delegates;

  public CompositeMetadataService(MetadataService... delegates) {
    this.delegates = Collections.unmodifiableList(Arrays.asList(delegates));
  }

  @Override
  public TrustRootsResult findTrustRoots(
      List<X509Certificate> attestationCertificateChain, Optional<ByteArray> aaguid) {
    for (MetadataService delegate : delegates) {
      TrustRootsResult res = delegate.findTrustRoots(attestationCertificateChain, aaguid);
      if (!res.getTrustRoots().isEmpty()) {
        return res;
      }
    }

    return TrustRootsResult.builder().trustRoots(Collections.emptySet()).build();
  }

  @Override
  public Set<Object> findEntries(@NonNull RegistrationResult registrationResult) {
    for (MetadataService delegate : delegates) {
      Set<Object> res = delegate.findEntries(registrationResult);
      if (!res.isEmpty()) {
        return res;
      }
    }

    return Collections.emptySet();
  }
}
