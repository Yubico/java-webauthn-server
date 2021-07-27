package com.yubico.fido.metadata;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import java.util.stream.Stream;
import lombok.EqualsAndHashCode;

/**
 * Enum-like collection of known <code>MATCHER_PROTECTION</code> values.
 *
 * <p>Constants in this class behave like enum constants. Use {@link #of(short)} to parse raw <code>
 * int</code> values.
 *
 * @see #of(short)
 * @see <a
 *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#matcher-protection-types">FIDO
 *     Registry of Predefined Values §3.3 Matcher Protection Types</a>
 */
@EqualsAndHashCode
public class MatcherProtectionType {

  /**
   * This flag must be set if the authenticator's matcher is running in software. Mutually exclusive
   * with {@link #MATCHER_PROTECTION_TEE}, {@link #MATCHER_PROTECTION_ON_CHIP}.
   *
   * <p>NOTE: The above requirements apply to authenticators; this library DOES NOT enforce them.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#matcher-protection-types">FIDO
   *     Registry of Predefined Values §3.3 Matcher Protection Types</a>
   */
  public static final MatcherProtectionType MATCHER_PROTECTION_SOFTWARE =
      new MatcherProtectionType((short) 0x0001, "SOFTWARE");

  /**
   * This flag should be set if the authenticator's matcher is running inside the Trusted Execution
   * Environment. Mutually exclusive with {@link #MATCHER_PROTECTION_SOFTWARE}, {@link
   * #MATCHER_PROTECTION_ON_CHIP}.
   *
   * <p>NOTE: The above requirements apply to authenticators; this library DOES NOT enforce them.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#matcher-protection-types">FIDO
   *     Registry of Predefined Values §3.3 Matcher Protection Types</a>
   */
  public static final MatcherProtectionType MATCHER_PROTECTION_TEE =
      new MatcherProtectionType((short) 0x0002, "TEE");

  /**
   * This flag should be set if the authenticator's matcher is running on the chip. Mutually
   * exclusive with {@link #MATCHER_PROTECTION_TEE}, {@link #MATCHER_PROTECTION_SOFTWARE}.
   *
   * <p>NOTE: The above requirements apply to authenticators; this library DOES NOT enforce them.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#matcher-protection-types">FIDO
   *     Registry of Predefined Values §3.3 Matcher Protection Types</a>
   */
  public static final MatcherProtectionType MATCHER_PROTECTION_ON_CHIP =
      new MatcherProtectionType((short) 0x0004, "ON_CHIP");

  @JsonValue public final short value;

  @EqualsAndHashCode.Exclude private final transient String name;

  private MatcherProtectionType(short value, String name) {
    this.value = value;
    this.name = name;
  }

  /**
   * @return An array containing all predefined values of {@link MatcherProtectionType} known by
   *     this implementation.
   */
  public static MatcherProtectionType[] values() {
    return new MatcherProtectionType[] {
      MATCHER_PROTECTION_SOFTWARE, MATCHER_PROTECTION_TEE, MATCHER_PROTECTION_ON_CHIP
    };
  }

  /**
   * @return If <code>value</code> is the same as that of any of the constants in {@link
   *     MatcherProtectionType}, returns that constant instance. Otherwise returns a new instance
   *     containing <code>value</code>.
   */
  @JsonCreator
  public static MatcherProtectionType of(short value) {
    return Stream.of(values())
        .filter(v -> v.value == value)
        .findAny()
        .orElseGet(() -> new MatcherProtectionType(value, null));
  }

  @Override
  public String toString() {
    if (name == null) {
      return String.format("%s(%04x)", MatcherProtectionType.class.getSimpleName(), value);
    } else {
      return name;
    }
  }
}
