package com.yubico.fido.metadata;

import com.fasterxml.jackson.annotation.JsonValue;

/**
 * The ATTESTATION constants are 16 bit long integers indicating the specific attestation that
 * authenticator supports.
 *
 * <p>Each constant has a case-sensitive string representation (in quotes), which is used in the
 * authoritative metadata for FIDO authenticators. *
 *
 * @see <a
 *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#authenticator-attestation-types">FIDO
 *     Registry of Predefined Values §3.7 Authenticator Attestation Types</a>
 */
public enum AuthenticatorAttestationType {

  /**
   * Indicates full basic attestation, based on an attestation private key shared among a class of
   * authenticators (e.g. same model). Authenticators must provide its attestation signature during
   * the registration process for the same reason. The attestation trust anchor is shared with FIDO
   * Servers out of band (as part of the Metadata). This sharing process should be done according to
   * [<a
   * href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#bib-FIDOMetadataService">FIDOMetadataService</a>].
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#authenticator-attestation-types">FIDO
   *     Registry of Predefined Values §3.7 Authenticator Attestation Types</a>
   */
  ATTESTATION_BASIC_FULL(0x3E07, "basic_full"),

  /**
   * Just syntactically a Basic Attestation. The attestation object self-signed, i.e. it is signed
   * using the UAuth.priv key, i.e. the key corresponding to the UAuth.pub key included in the
   * attestation object. As a consequence it does not provide a cryptographic proof of the security
   * characteristics. But it is the best thing we can do if the authenticator is not able to have an
   * attestation private key.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#authenticator-attestation-types">FIDO
   *     Registry of Predefined Values §3.7 Authenticator Attestation Types</a>
   */
  ATTESTATION_BASIC_SURROGATE(0x3E08, "basic_surrogate"),

  /**
   * Indicates use of elliptic curve based direct anonymous attestation as defined in [<a
   * href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#bib-FIDOEcdaaAlgorithm">FIDOEcdaaAlgorithm</a>].
   * Support for this attestation type is optional at this time. It might be required by FIDO
   * Certification.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#authenticator-attestation-types">FIDO
   *     Registry of Predefined Values §3.7 Authenticator Attestation Types</a>
   */
  ATTESTATION_ECDAA(0x3E09, "ecdaa"),

  /**
   * Indicates PrivacyCA attestation as defined in [<a
   * href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#bib-TCG-CMCProfile-AIKCertEnroll">TCG-CMCProfile-AIKCertEnroll</a>].
   * Support for this attestation type is optional at this time. It might be required by FIDO
   * Certification.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#authenticator-attestation-types">FIDO
   *     Registry of Predefined Values §3.7 Authenticator Attestation Types</a>
   */
  ATTESTATION_ATTCA(0x3E0A, "attca"),

  /**
   * In this case, the authenticator uses an Anonymization CA which dynamically generates
   * per-credential attestation certificates such that the attestation statements presented to
   * Relying Parties do not provide uniquely identifiable information, e.g., that might be used for
   * tracking purposes. The applicable [<a
   * href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#bib-WebAuthn">WebAuthn</a>]
   * attestation formats "fmt" are Google SafetyNet Attestation "android-safetynet", Android
   * Keystore Attestation "android-key", Apple Anonymous Attestation "apple", and Apple Application
   * Attestation "apple-appattest".
   */
  ATTESTATION_ANONCA(0x3E0C, "anonca"),

  /** Indicates absence of attestation. */
  ATTESTATION_NONE(0x3E0B, "none");

  private final int value;

  @JsonValue private final String name;

  AuthenticatorAttestationType(int value, String name) {
    this.value = value;
    this.name = name;
  }
}
