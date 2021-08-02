package com.yubico.fido.metadata;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import java.util.stream.Stream;
import lombok.EqualsAndHashCode;

/**
 * Enum-like collection of known <code>USER_VERIFY</code> values.
 *
 * <p>Constants in this class behave like enum constants. Use {@link #of(int)} to parse raw <code>
 * int</code> values.
 *
 * @see #of(int)
 * @see <a
 *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#user-verification-methods">FIDO
 *     Registry of Predefined Values §3.1 User Verification Methods</a>
 */
@EqualsAndHashCode
public class UserVerificationMethod {

  /**
   * This flag MUST be set if the authenticator is able to confirm user presence in any fashion. If
   * this flag and no other is set for user verification, the guarantee is only that the
   * authenticator cannot be operated without some human intervention, not necessarily that the
   * sensing of "presence" provides any level of user verification (e.g. a device that requires a
   * button press to activate).
   *
   * <p>NOTE: The above requirements apply to authenticators; this library DOES NOT enforce them.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#user-verification-methods">FIDO
   *     Registry of Predefined Values §3.1 User Verification Methods</a>
   */
  public static final UserVerificationMethod USER_VERIFY_PRESENCE =
      new UserVerificationMethod(0x00000001, "PRESENCE");

  /**
   * This flag MUST be set if the authenticator uses any type of measurement of a fingerprint for
   * user verification.
   *
   * <p>NOTE: The above requirements apply to authenticators; this library DOES NOT enforce them.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#user-verification-methods">FIDO
   *     Registry of Predefined Values §3.1 User Verification Methods</a>
   */
  public static final UserVerificationMethod USER_VERIFY_FINGERPRINT =
      new UserVerificationMethod(0x00000002, "FINGERPRINT");

  /**
   * This flag MUST be set if the authenticator uses a local-only passcode (i.e. a passcode not
   * known by the server) for user verification.
   *
   * <p>NOTE: The above requirements apply to authenticators; this library DOES NOT enforce them.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#user-verification-methods">FIDO
   *     Registry of Predefined Values §3.1 User Verification Methods</a>
   */
  public static final UserVerificationMethod USER_VERIFY_PASSCODE =
      new UserVerificationMethod(0x00000004, "PASSCODE");

  /**
   * This flag MUST be set if the authenticator uses a voiceprint (also known as speaker
   * recognition) for user verification.
   *
   * <p>NOTE: The above requirements apply to authenticators; this library DOES NOT enforce them.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#user-verification-methods">FIDO
   *     Registry of Predefined Values §3.1 User Verification Methods</a>
   */
  public static final UserVerificationMethod USER_VERIFY_VOICEPRINT =
      new UserVerificationMethod(0x00000008, "VOICEPRINT");

  /**
   * This flag MUST be set if the authenticator uses any manner of face recognition to verify the
   * user.
   *
   * <p>NOTE: The above requirements apply to authenticators; this library DOES NOT enforce them.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#user-verification-methods">FIDO
   *     Registry of Predefined Values §3.1 User Verification Methods</a>
   */
  public static final UserVerificationMethod USER_VERIFY_FACEPRINT =
      new UserVerificationMethod(0x00000010, "FACEPRINT");

  /**
   * This flag MUST be set if the authenticator uses any form of location sensor or measurement for
   * user verification.
   *
   * <p>NOTE: The above requirements apply to authenticators; this library DOES NOT enforce them.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#user-verification-methods">FIDO
   *     Registry of Predefined Values §3.1 User Verification Methods</a>
   */
  public static final UserVerificationMethod USER_VERIFY_LOCATION =
      new UserVerificationMethod(0x00000020, "LOCATION");

  /**
   * This flag MUST be set if the authenticator uses any form of eye biometrics for user
   * verification.
   *
   * <p>NOTE: The above requirements apply to authenticators; this library DOES NOT enforce them.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#user-verification-methods">FIDO
   *     Registry of Predefined Values §3.1 User Verification Methods</a>
   */
  public static final UserVerificationMethod USER_VERIFY_EYEPRINT =
      new UserVerificationMethod(0x00000040, "EYEPRINT");

  /**
   * This flag MUST be set if the authenticator uses a drawn pattern for user verification.
   *
   * <p>NOTE: The above requirements apply to authenticators; this library DOES NOT enforce them.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#user-verification-methods">FIDO
   *     Registry of Predefined Values §3.1 User Verification Methods</a>
   */
  public static final UserVerificationMethod USER_VERIFY_PATTERN =
      new UserVerificationMethod(0x00000080, "PATTERN");

  /**
   * This flag MUST be set if the authenticator uses any measurement of a full hand (including
   * palm-print, hand geometry or vein geometry) for user verification.
   *
   * <p>NOTE: The above requirements apply to authenticators; this library DOES NOT enforce them.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#user-verification-methods">FIDO
   *     Registry of Predefined Values §3.1 User Verification Methods</a>
   */
  public static final UserVerificationMethod USER_VERIFY_HANDPRINT =
      new UserVerificationMethod(0x00000100, "HANDPRINT");

  /**
   * This flag MUST be set if the authenticator will respond without any user interaction (e.g.
   * Silent Authenticator).
   *
   * <p>NOTE: The above requirements apply to authenticators; this library DOES NOT enforce them.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#user-verification-methods">FIDO
   *     Registry of Predefined Values §3.1 User Verification Methods</a>
   */
  public static final UserVerificationMethod USER_VERIFY_NONE =
      new UserVerificationMethod(0x00000200, "NONE");

  /**
   * If an authenticator sets multiple flags for user verification types, it MAY also set this flag
   * to indicate that all verification methods will be enforced (e.g. faceprint AND voiceprint). If
   * flags for multiple user verification methods are set and this flag is not set, verification
   * with only one is necessary (e.g. fingerprint OR passcode).
   *
   * <p>NOTE: The above requirements apply to authenticators; this library DOES NOT enforce them.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#user-verification-methods">FIDO
   *     Registry of Predefined Values §3.1 User Verification Methods</a>
   */
  public static final UserVerificationMethod USER_VERIFY_ALL =
      new UserVerificationMethod(0x00000400, "ALL");

  @JsonValue public final int value;

  @EqualsAndHashCode.Exclude private final transient String name;

  private UserVerificationMethod(int value, String name) {
    this.value = value;
    this.name = name;
  }

  /**
   * @return An array containing all predefined values of {@link UserVerificationMethod} known by
   *     this implementation.
   */
  public static UserVerificationMethod[] values() {
    return new UserVerificationMethod[] {
      USER_VERIFY_PRESENCE,
      USER_VERIFY_FINGERPRINT,
      USER_VERIFY_PASSCODE,
      USER_VERIFY_VOICEPRINT,
      USER_VERIFY_FACEPRINT,
      USER_VERIFY_LOCATION,
      USER_VERIFY_EYEPRINT,
      USER_VERIFY_PATTERN,
      USER_VERIFY_HANDPRINT,
      USER_VERIFY_NONE,
      USER_VERIFY_ALL
    };
  }

  /**
   * @return If <code>value</code> is the same as that of any of the constants in {@link
   *     UserVerificationMethod}, returns that constant instance. Otherwise returns a new instance
   *     containing <code>value</code>.
   */
  @JsonCreator
  public static UserVerificationMethod of(int value) {
    return Stream.of(values())
        .filter(v -> v.value == value)
        .findAny()
        .orElseGet(() -> new UserVerificationMethod(value, null));
  }

  @Override
  public String toString() {
    if (name == null) {
      return String.format("%s(%04x)", UserVerificationMethod.class.getSimpleName(), value);
    } else {
      return "USER_VERIFY_" + name;
    }
  }
}
