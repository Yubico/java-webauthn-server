package com.yubico.fido.metadata;

import java.time.LocalDate;
import java.util.Optional;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;
import lombok.extern.jackson.Jacksonized;

/**
 * Contains the current BiometricStatusReport of one of the authenticator’s biometric component.
 *
 * @see <a
 *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#biometricstatusreport-dictionary">FIDO
 *     Metadata Service §3.1.2. BiometricStatusReport dictionary</a>
 */
@Value
@Builder(toBuilder = true)
@Jacksonized
public class BiometricStatusReport {

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#biometricstatusreport-dictionary">FIDO
   *     Metadata Service §3.1.2. BiometricStatusReport dictionary</a>
   */
  int certLevel;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#biometricstatusreport-dictionary">FIDO
   *     Metadata Service §3.1.2. BiometricStatusReport dictionary</a>
   */
  @NonNull UserVerificationMethod modality;

  LocalDate effectiveDate;
  String certificationDescriptor;
  String certificateNumber;
  String certificationPolicyVersion;
  String certificationRequirementsVersion;

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#biometricstatusreport-dictionary">FIDO
   *     Metadata Service §3.1.2. BiometricStatusReport dictionary</a>
   */
  public Optional<LocalDate> getEffectiveDate() {
    return Optional.ofNullable(effectiveDate);
  }

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#biometricstatusreport-dictionary">FIDO
   *     Metadata Service §3.1.2. BiometricStatusReport dictionary</a>
   */
  public Optional<String> getCertificationDescriptor() {
    return Optional.ofNullable(certificationDescriptor);
  }

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#biometricstatusreport-dictionary">FIDO
   *     Metadata Service §3.1.2. BiometricStatusReport dictionary</a>
   */
  public Optional<String> getCertificateNumber() {
    return Optional.ofNullable(certificateNumber);
  }

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#biometricstatusreport-dictionary">FIDO
   *     Metadata Service §3.1.2. BiometricStatusReport dictionary</a>
   */
  public Optional<String> getCertificationPolicyVersion() {
    return Optional.ofNullable(certificationPolicyVersion);
  }

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#biometricstatusreport-dictionary">FIDO
   *     Metadata Service §3.1.2. BiometricStatusReport dictionary</a>
   */
  public Optional<String> getCertificationRequirementsVersion() {
    return Optional.ofNullable(certificationRequirementsVersion);
  }
}
