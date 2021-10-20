package com.yubico.fido.metadata;

import com.fasterxml.jackson.annotation.JsonValue;

/**
 * The ALG_KEY constants are 16 bit long integers indicating the specific Public Key algorithm and
 * encoding.
 *
 * <p>Each constant has a case-sensitive string representation (in quotes), which is used in the
 * authoritative metadata for FIDO authenticators.
 *
 * @see <a
 *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#public-key-representation-formats">FIDO
 *     Registry of Predefined Values §3.6.2 Public Key Representation Formats</a>
 */
public enum PublicKeyRepresentationFormat {

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#public-key-representation-formats">FIDO
   *     Registry of Predefined Values §3.6.2 Public Key Representation Formats</a>
   */
  ALG_KEY_ECC_X962_RAW(0x0100, "ecc_x962_raw"),

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#public-key-representation-formats">FIDO
   *     Registry of Predefined Values §3.6.2 Public Key Representation Formats</a>
   */
  ALG_KEY_ECC_X962_DER(0x0101, "ecc_x962_der"),

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#public-key-representation-formats">FIDO
   *     Registry of Predefined Values §3.6.2 Public Key Representation Formats</a>
   */
  ALG_KEY_RSA_2048_RAW(0x0102, "rsa_2048_raw"),

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#public-key-representation-formats">FIDO
   *     Registry of Predefined Values §3.6.2 Public Key Representation Formats</a>
   */
  ALG_KEY_RSA_2048_DER(0x0103, "rsa_2048_der"),

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#public-key-representation-formats">FIDO
   *     Registry of Predefined Values §3.6.2 Public Key Representation Formats</a>
   */
  ALG_KEY_COSE(0x0104, "cose");

  private final int value;

  @JsonValue private final String name;

  PublicKeyRepresentationFormat(int value, String name) {
    this.value = value;
    this.name = name;
  }
}
