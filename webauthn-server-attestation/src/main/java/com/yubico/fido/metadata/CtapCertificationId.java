package com.yubico.fido.metadata;

import com.fasterxml.jackson.annotation.JsonValue;

/**
 * The {@link AuthenticatorGetInfo#getCertifications()} member provides a hint to the platform with
 * additional information about certifications that the authenticator has received. Certification
 * programs may revoke certification of specific devices at any time. Relying partys are responsible
 * for validating attestations and AAGUID via appropriate methods. Platforms may alter their
 * behaviour based on these hints such as selecting a PIN protocol or credProtect level.
 *
 * @see <a
 *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-feature-descriptions-certifications">Client
 *     to Authenticator Protocol (CTAP) §7.3. Authenticator Certifications</a>
 */
public enum CtapCertificationId {

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-feature-descriptions-certifications">Client
   *     to Authenticator Protocol (CTAP) §7.3. Authenticator Certifications</a>
   */
  FIPS_CMVP_2("FIPS-CMVP-2"),

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-feature-descriptions-certifications">Client
   *     to Authenticator Protocol (CTAP) §7.3. Authenticator Certifications</a>
   */
  FIPS_CMVP_3("FIPS-CMVP-3"),

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-feature-descriptions-certifications">Client
   *     to Authenticator Protocol (CTAP) §7.3. Authenticator Certifications</a>
   */
  FIPS_CMVP_2_PHY("FIPS-CMVP-2-PHY"),

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-feature-descriptions-certifications">Client
   *     to Authenticator Protocol (CTAP) §7.3. Authenticator Certifications</a>
   */
  FIPS_CMVP_3_PHY("FIPS-CMVP-3-PHY"),

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-feature-descriptions-certifications">Client
   *     to Authenticator Protocol (CTAP) §7.3. Authenticator Certifications</a>
   */
  CC_EAL("CC-EAL"),

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#sctn-feature-descriptions-certifications">Client
   *     to Authenticator Protocol (CTAP) §7.3. Authenticator Certifications</a>
   */
  FIDO("FIDO");

  @JsonValue private final String id;

  CtapCertificationId(String id) {
    this.id = id;
  }
}
