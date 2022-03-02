package com.yubico.fido.metadata;

import com.fasterxml.jackson.annotation.JsonEnumDefaultValue;

/**
 * This enumeration describes the status of an authenticator model as identified by its AAID/AAGUID
 * or attestationCertificateKeyIdentifiers and potentially some additional information (such as a
 * specific attestation key).
 *
 * @see <a
 *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#enumdef-authenticatorstatus">FIDO
 *     Metadata Service §3.1.4. AuthenticatorStatus enum</a>
 */
public enum AuthenticatorStatus {
  /** (NOT DEFINED IN SPEC) Placeholder for any unknown {@link AuthenticatorStatus} value. */
  @JsonEnumDefaultValue
  UNKNOWN(0),

  /**
   * This authenticator is not FIDO certified.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#enumdef-authenticatorstatus">FIDO
   *     Metadata Service §3.1.4. AuthenticatorStatus enum</a>
   */
  NOT_FIDO_CERTIFIED(0),

  /**
   * This authenticator has passed FIDO functional certification. This certification scheme is
   * phased out and will be replaced by {@link #FIDO_CERTIFIED_L1}.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#enumdef-authenticatorstatus">FIDO
   *     Metadata Service §3.1.4. AuthenticatorStatus enum</a>
   */
  FIDO_CERTIFIED(10),

  /**
   * Indicates that malware is able to bypass the user verification. This means that the
   * authenticator could be used without the user’s consent and potentially even without the user’s
   * knowledge.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#enumdef-authenticatorstatus">FIDO
   *     Metadata Service §3.1.4. AuthenticatorStatus enum</a>
   */
  USER_VERIFICATION_BYPASS(0),

  /**
   * Indicates that an attestation key for this authenticator is known to be compromised. The
   * relying party SHOULD check the certificate field and use it to identify the compromised
   * authenticator batch. If the certificate field is not set, the relying party should reject all
   * new registrations of the compromised authenticator. The Authenticator manufacturer should set
   * the date to the date when compromise has occurred.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#enumdef-authenticatorstatus">FIDO
   *     Metadata Service §3.1.4. AuthenticatorStatus enum</a>
   */
  ATTESTATION_KEY_COMPROMISE(0),

  /**
   * This authenticator has identified weaknesses that allow registered keys to be compromised and
   * should not be trusted. This would include both, e.g. weak entropy that causes predictable keys
   * to be generated or side channels that allow keys or signatures to be forged, guessed or
   * extracted.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#enumdef-authenticatorstatus">FIDO
   *     Metadata Service §3.1.4. AuthenticatorStatus enum</a>
   */
  USER_KEY_REMOTE_COMPROMISE(0),

  /**
   * This authenticator has known weaknesses in its key protection mechanism(s) that allow user keys
   * to be extracted by an adversary in physical possession of the device.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#enumdef-authenticatorstatus">FIDO
   *     Metadata Service §3.1.4. AuthenticatorStatus enum</a>
   */
  USER_KEY_PHYSICAL_COMPROMISE(0),

  /**
   * A software or firmware update is available for the device. The Authenticator manufacturer
   * should set the url to the URL where users can obtain an update and the date the update was
   * published. When this status code is used, then the field authenticatorVersion in the
   * authenticator Metadata Statement [<a
   * href="https://fidoalliance.org/specs/mds/fido-metadata-statement-v3.0-ps-20210518.html">FIDOMetadataStatement</a>]
   * MUST be updated, if the update fixes severe security issues, e.g. the ones reported by
   * preceding StatusReport entries with status code {@link #USER_VERIFICATION_BYPASS}, {@link
   * #ATTESTATION_KEY_COMPROMISE}, {@link #USER_KEY_REMOTE_COMPROMISE}, {@link
   * #USER_KEY_PHYSICAL_COMPROMISE}, {@link #REVOKED}. The Relying party MUST reject the Metadata
   * Statement if the authenticatorVersion has not increased
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#enumdef-authenticatorstatus">FIDO
   *     Metadata Service §3.1.4. AuthenticatorStatus enum</a>
   */
  UPDATE_AVAILABLE(0),

  /**
   * The FIDO Alliance has determined that this authenticator should not be trusted for any reason.
   * For example if it is known to be a fraudulent product or contain a deliberate backdoor. Relying
   * parties SHOULD reject any future registration of this authenticator model.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#enumdef-authenticatorstatus">FIDO
   *     Metadata Service §3.1.4. AuthenticatorStatus enum</a>
   */
  REVOKED(0),

  /**
   * The authenticator vendor has completed and submitted the self-certification checklist to the
   * FIDO Alliance. If this completed checklist is publicly available, the URL will be specified in
   * url.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#enumdef-authenticatorstatus">FIDO
   *     Metadata Service §3.1.4. AuthenticatorStatus enum</a>
   */
  SELF_ASSERTION_SUBMITTED(0),

  /**
   * The authenticator has passed FIDO Authenticator certification at level 1. This level is the
   * more strict successor of {@link #FIDO_CERTIFIED}.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#enumdef-authenticatorstatus">FIDO
   *     Metadata Service §3.1.4. AuthenticatorStatus enum</a>
   */
  FIDO_CERTIFIED_L1(10),

  /**
   * The authenticator has passed FIDO Authenticator certification at level 1+. This level is the
   * more than level 1.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#enumdef-authenticatorstatus">FIDO
   *     Metadata Service §3.1.4. AuthenticatorStatus enum</a>
   */
  FIDO_CERTIFIED_L1plus(11),

  /**
   * The authenticator has passed FIDO Authenticator certification at level 2. This level is more
   * strict than level 1+.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#enumdef-authenticatorstatus">FIDO
   *     Metadata Service §3.1.4. AuthenticatorStatus enum</a>
   */
  FIDO_CERTIFIED_L2(20),

  /**
   * The authenticator has passed FIDO Authenticator certification at level 2+. This level is more
   * strict than level 2.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#enumdef-authenticatorstatus">FIDO
   *     Metadata Service §3.1.4. AuthenticatorStatus enum</a>
   */
  FIDO_CERTIFIED_L2plus(21),

  /**
   * The authenticator has passed FIDO Authenticator certification at level 3. This level is more
   * strict than level 2+.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#enumdef-authenticatorstatus">FIDO
   *     Metadata Service §3.1.4. AuthenticatorStatus enum</a>
   */
  FIDO_CERTIFIED_L3(30),

  /**
   * The authenticator has passed FIDO Authenticator certification at level 3+. This level is more
   * strict than level 3.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/mds/fido-metadata-service-v3.0-ps-20210518.html#enumdef-authenticatorstatus">FIDO
   *     Metadata Service §3.1.4. AuthenticatorStatus enum</a>
   */
  FIDO_CERTIFIED_L3plus(31);

  int certificationLevel;

  AuthenticatorStatus(int certificationLevel) {
    this.certificationLevel = certificationLevel;
  }
}
