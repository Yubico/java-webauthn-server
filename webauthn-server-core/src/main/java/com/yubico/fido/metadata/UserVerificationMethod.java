package com.yubico.fido.metadata;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import java.util.stream.Stream;
import lombok.Getter;

/**
 * The USER_VERIFY constants are flags in a bitfield represented as a 32 bit long integer. They
 * describe the methods and capabilities of a FIDO authenticator for locally verifying a user. The
 * operational details of these methods are opaque to the server. These constants are used in the
 * authoritative metadata for FIDO authenticators, reported and queried through the UAF Discovery
 * APIs, and used to form authenticator policies in UAF protocol messages. Each constant has a
 * case-sensitive string representation (in quotes), which is used in the authoritative metadata for
 * FIDO authenticators.
 *
 * @see #fromValue(int)
 * @see #fromName(String)
 * @see <a
 *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#user-verification-methods">FIDO
 *     Registry of Predefined Values §3.1 User Verification Methods</a>
 */
@Getter
public enum UserVerificationMethod {

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
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#user-verification-methods">FIDO
   *     Registry of Predefined Values §3.1 User Verification Methods</a>
   */
  USER_VERIFY_PRESENCE_INTERNAL(0x00000001, "presence_internal"),

  /**
   * This flag MUST be set if the authenticator uses any type of measurement of a fingerprint for
   * user verification.
   *
   * <p>NOTE: The above requirements apply to authenticators; this library DOES NOT enforce them.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#user-verification-methods">FIDO
   *     Registry of Predefined Values §3.1 User Verification Methods</a>
   */
  USER_VERIFY_FINGERPRINT_INTERNAL(0x00000002, "fingerprint_internal"),

  /**
   * This flag MUST be set if the authenticator uses a local-only passcode (i.e. a passcode not
   * known by the server) for user verification.
   *
   * <p>NOTE: The above requirements apply to authenticators; this library DOES NOT enforce them.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#user-verification-methods">FIDO
   *     Registry of Predefined Values §3.1 User Verification Methods</a>
   */
  USER_VERIFY_PASSCODE_INTERNAL(0x00000004, "passcode_internal"),

  /**
   * This flag MUST be set if the authenticator uses a voiceprint (also known as speaker
   * recognition) for user verification.
   *
   * <p>NOTE: The above requirements apply to authenticators; this library DOES NOT enforce them.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#user-verification-methods">FIDO
   *     Registry of Predefined Values §3.1 User Verification Methods</a>
   */
  USER_VERIFY_VOICEPRINT_INTERNAL(0x00000008, "voiceprint_internal"),

  /**
   * This flag MUST be set if the authenticator uses any manner of face recognition to verify the
   * user.
   *
   * <p>NOTE: The above requirements apply to authenticators; this library DOES NOT enforce them.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#user-verification-methods">FIDO
   *     Registry of Predefined Values §3.1 User Verification Methods</a>
   */
  USER_VERIFY_FACEPRINT_INTERNAL(0x00000010, "faceprint_internal"),

  /**
   * This flag MUST be set if the authenticator uses any form of location sensor or measurement for
   * user verification.
   *
   * <p>NOTE: The above requirements apply to authenticators; this library DOES NOT enforce them.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#user-verification-methods">FIDO
   *     Registry of Predefined Values §3.1 User Verification Methods</a>
   */
  USER_VERIFY_LOCATION_INTERNAL(0x00000020, "location_internal"),

  /**
   * This flag MUST be set if the authenticator uses any form of eye biometrics for user
   * verification.
   *
   * <p>NOTE: The above requirements apply to authenticators; this library DOES NOT enforce them.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#user-verification-methods">FIDO
   *     Registry of Predefined Values §3.1 User Verification Methods</a>
   */
  USER_VERIFY_EYEPRINT_INTERNAL(0x00000040, "eyeprint_internal"),

  /**
   * This flag MUST be set if the authenticator uses a drawn pattern for user verification.
   *
   * <p>NOTE: The above requirements apply to authenticators; this library DOES NOT enforce them.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#user-verification-methods">FIDO
   *     Registry of Predefined Values §3.1 User Verification Methods</a>
   */
  USER_VERIFY_PATTERN_INTERNAL(0x00000080, "pattern_internal"),

  /**
   * This flag MUST be set if the authenticator uses any measurement of a full hand (including
   * palm-print, hand geometry or vein geometry) for user verification.
   *
   * <p>NOTE: The above requirements apply to authenticators; this library DOES NOT enforce them.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#user-verification-methods">FIDO
   *     Registry of Predefined Values §3.1 User Verification Methods</a>
   */
  USER_VERIFY_HANDPRINT_INTERNAL(0x00000100, "handprint_internal"),

  /**
   * This flag MUST be set if the authenticator uses a local-only passcode (i.e. a passcode not
   * known by the server) for user verification that might be gathered outside the authenticator
   * boundary.
   *
   * <p>NOTE: The above requirements apply to authenticators; this library DOES NOT enforce them.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#user-verification-methods">FIDO
   *     Registry of Predefined Values §3.1 User Verification Methods</a>
   */
  USER_VERIFY_PASSCODE_EXTERNAL(0x00000800, "passcode_external"),

  /**
   * This flag MUST be set if the authenticator uses a drawn pattern for user verification that
   * might be gathered outside the authenticator boundary.
   *
   * <p>NOTE: The above requirements apply to authenticators; this library DOES NOT enforce them.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#user-verification-methods">FIDO
   *     Registry of Predefined Values §3.1 User Verification Methods</a>
   */
  USER_VERIFY_PATTERN_EXTERNAL(0x00001000, "pattern_external"),

  /**
   * This flag MUST be set if the authenticator will respond without any user interaction (e.g.
   * Silent Authenticator).
   *
   * <p>NOTE: The above requirements apply to authenticators; this library DOES NOT enforce them.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#user-verification-methods">FIDO
   *     Registry of Predefined Values §3.1 User Verification Methods</a>
   */
  USER_VERIFY_NONE(0x00000200, "none"),

  /**
   * If an authenticator sets multiple flags for the "_INTERNAL" and/or "_EXTERNAL" user
   * verification types, it MAY also set this flag to indicate that all verification methods with
   * respective flags set will be enforced (e.g. faceprint AND voiceprint). If flags for multiple
   * user verification methods are set and this flag is not set, verification with only one is
   * necessary (e.g. fingerprint OR passcode).
   *
   * <p>NOTE: The above requirements apply to authenticators; this library DOES NOT enforce them.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#user-verification-methods">FIDO
   *     Registry of Predefined Values §3.1 User Verification Methods</a>
   */
  USER_VERIFY_ALL(0x00000400, "all");

  private final int value;

  @JsonValue private final String name;

  UserVerificationMethod(int value, String name) {
    this.value = value;
    this.name = name;
  }

  /**
   * @return If <code>value</code> matches any {@link UserVerificationMethod} constant, returns that
   *     constant instance. Otherwise throws {@link IllegalArgumentException}.
   */
  public static UserVerificationMethod fromValue(int value) {
    return Stream.of(values())
        .filter(v -> v.value == value)
        .findAny()
        .orElseThrow(
            () ->
                new IllegalArgumentException(
                    String.format(
                        "Unknown %s value: 0x%04x", UserVerificationMethod.class, value)));
  }

  /**
   * @return If <code>name</code> matches any {@link UserVerificationMethod} constant, returns that
   *     constant instance. Otherwise throws {@link IllegalArgumentException}.
   */
  @JsonCreator
  public static UserVerificationMethod fromName(String name) {
    return Stream.of(values())
        .filter(v -> v.name.equals(name))
        .findAny()
        .orElseThrow(
            () ->
                new IllegalArgumentException(
                    String.format("Unknown %s name: %s", UserVerificationMethod.class, name)));
  }
}
