package com.yubico.fido.metadata;

import com.fasterxml.jackson.annotation.JsonValue;

/**
 * The <code>ALG_SIGN</code> constants are 16 bit long integers indicating the specific signature
 * algorithm and encoding.
 *
 * <p>Each constant has a case-sensitive string representation (in quotes), which is used in the
 * authoritative metadata for FIDO authenticators.
 *
 * @see <a
 *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#authentication-algorithms">FIDO
 *     Registry of Predefined Values §3.6.1 Authentication Algorithms</a>
 */
public enum AuthenticationAlgorithm {

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#authentication-algorithms">FIDO
   *     Registry of Predefined Values §3.6.1 Authentication Algorithms</a>
   */
  ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW(0x0001, "secp256r1_ecdsa_sha256_raw"),

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#authentication-algorithms">FIDO
   *     Registry of Predefined Values §3.6.1 Authentication Algorithms</a>
   */
  ALG_SIGN_SECP256R1_ECDSA_SHA256_DER(0x0002, "secp256r1_ecdsa_sha256_der"),

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#authentication-algorithms">FIDO
   *     Registry of Predefined Values §3.6.1 Authentication Algorithms</a>
   */
  ALG_SIGN_RSASSA_PSS_SHA256_RAW(0x0003, "rsassa_pss_sha256_raw"),

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#authentication-algorithms">FIDO
   *     Registry of Predefined Values §3.6.1 Authentication Algorithms</a>
   */
  ALG_SIGN_RSASSA_PSS_SHA256_DER(0x0004, "rsassa_pss_sha256_der"),

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#authentication-algorithms">FIDO
   *     Registry of Predefined Values §3.6.1 Authentication Algorithms</a>
   */
  ALG_SIGN_SECP256K1_ECDSA_SHA256_RAW(0x0005, "secp256k1_ecdsa_sha256_raw"),

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#authentication-algorithms">FIDO
   *     Registry of Predefined Values §3.6.1 Authentication Algorithms</a>
   */
  ALG_SIGN_SECP256K1_ECDSA_SHA256_DER(0x0006, "secp256k1_ecdsa_sha256_der"),

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#authentication-algorithms">FIDO
   *     Registry of Predefined Values §3.6.1 Authentication Algorithms</a>
   */
  ALG_SIGN_RSA_EMSA_PKCS1_SHA256_RAW(0x0008, "rsa_emsa_pkcs1_sha256_raw"),

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#authentication-algorithms">FIDO
   *     Registry of Predefined Values §3.6.1 Authentication Algorithms</a>
   */
  ALG_SIGN_RSA_EMSA_PKCS1_SHA256_DER(0x0009, "rsa_emsa_pkcs1_sha256_der"),

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#authentication-algorithms">FIDO
   *     Registry of Predefined Values §3.6.1 Authentication Algorithms</a>
   */
  ALG_SIGN_RSASSA_PSS_SHA384_RAW(0x000A, "rsassa_pss_sha384_raw"),

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#authentication-algorithms">FIDO
   *     Registry of Predefined Values §3.6.1 Authentication Algorithms</a>
   */
  ALG_SIGN_RSASSA_PSS_SHA512_RAW(0x000B, "rsassa_pss_sha512_raw"),

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#authentication-algorithms">FIDO
   *     Registry of Predefined Values §3.6.1 Authentication Algorithms</a>
   */
  ALG_SIGN_RSASSA_PKCSV15_SHA256_RAW(0x000C, "rsassa_pkcsv15_sha256_raw"),

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#authentication-algorithms">FIDO
   *     Registry of Predefined Values §3.6.1 Authentication Algorithms</a>
   */
  ALG_SIGN_RSASSA_PKCSV15_SHA384_RAW(0x000D, "rsassa_pkcsv15_sha384_raw"),

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#authentication-algorithms">FIDO
   *     Registry of Predefined Values §3.6.1 Authentication Algorithms</a>
   */
  ALG_SIGN_RSASSA_PKCSV15_SHA512_RAW(0x000E, "rsassa_pkcsv15_sha512_raw"),

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#authentication-algorithms">FIDO
   *     Registry of Predefined Values §3.6.1 Authentication Algorithms</a>
   */
  ALG_SIGN_RSASSA_PKCSV15_SHA1_RAW(0x000F, "rsassa_pkcsv15_sha1_raw"),

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#authentication-algorithms">FIDO
   *     Registry of Predefined Values §3.6.1 Authentication Algorithms</a>
   */
  ALG_SIGN_SECP384R1_ECDSA_SHA384_RAW(0x0010, "secp384r1_ecdsa_sha384_raw"),

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#authentication-algorithms">FIDO
   *     Registry of Predefined Values §3.6.1 Authentication Algorithms</a>
   */
  ALG_SIGN_SECP521R1_ECDSA_SHA512_RAW(0x0011, "secp521r1_ecdsa_sha512_raw"),

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#authentication-algorithms">FIDO
   *     Registry of Predefined Values §3.6.1 Authentication Algorithms</a>
   */
  ALG_SIGN_ED25519_EDDSA_SHA512_RAW(0x0012, "ed25519_eddsa_sha512_raw"),

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#authentication-algorithms">FIDO
   *     Registry of Predefined Values §3.6.1 Authentication Algorithms</a>
   */
  ALG_SIGN_ED448_EDDSA_SHA512_RAW(0x0013, "ed448_eddsa_sha512_raw");

  private final int value;

  @JsonValue private final String name;

  AuthenticationAlgorithm(int value, String name) {
    this.value = value;
    this.name = name;
  }
}
