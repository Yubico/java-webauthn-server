package com.yubico.fido.metadata;

import java.util.Optional;
import lombok.Builder;
import lombok.Value;
import lombok.extern.jackson.Jacksonized;

/**
 * The BiometricAccuracyDescriptor describes relevant accuracy/complexity aspects in the case of a
 * biometric user verification method, see [<a
 * href="https://fidoalliance.org/specs/biometric/requirements/Biometrics-Requirements-v2.0-fd-20201006.html">FIDOBiometricsRequirements</a>].
 *
 * <p>At least one of the values MUST be set. If the vendor doesn’t want to specify such values,
 * then {@link VerificationMethodDescriptor#getBaDesc()} MUST be omitted.
 *
 * @see <a
 *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#biometricaccuracydescriptor-dictionary">FIDO
 *     Metadata Statement §3.3. BiometricAccuracyDescriptor dictionary</a>
 */
@Value
@Builder(toBuilder = true)
@Jacksonized
public class BiometricAccuracyDescriptor {

  Double selfAttestedFRR;
  Double selfAttestedFAR;
  Integer maxTemplates;
  Integer maxRetries;
  Integer blockSlowdown;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#biometricaccuracydescriptor-dictionary">FIDO
   *     Metadata Statement §3.3. BiometricAccuracyDescriptor dictionary</a>
   */
  public Optional<Double> getSelfAttestedFRR() {
    return Optional.ofNullable(selfAttestedFRR);
  }

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#biometricaccuracydescriptor-dictionary">FIDO
   *     Metadata Statement §3.3. BiometricAccuracyDescriptor dictionary</a>
   */
  public Optional<Double> getSelfAttestedFAR() {
    return Optional.ofNullable(selfAttestedFAR);
  }

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#biometricaccuracydescriptor-dictionary">FIDO
   *     Metadata Statement §3.3. BiometricAccuracyDescriptor dictionary</a>
   */
  public Optional<Integer> getMaxTemplates() {
    return Optional.ofNullable(maxTemplates);
  }

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#biometricaccuracydescriptor-dictionary">FIDO
   *     Metadata Statement §3.3. BiometricAccuracyDescriptor dictionary</a>
   */
  public Optional<Integer> getMaxRetries() {
    return Optional.ofNullable(maxRetries);
  }

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html#biometricaccuracydescriptor-dictionary">FIDO
   *     Metadata Statement §3.3. BiometricAccuracyDescriptor dictionary</a>
   */
  public Optional<Integer> getBlockSlowdown() {
    return Optional.ofNullable(blockSlowdown);
  }
}
