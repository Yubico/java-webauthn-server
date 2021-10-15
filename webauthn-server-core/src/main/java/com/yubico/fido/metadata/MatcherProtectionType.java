package com.yubico.fido.metadata;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import java.util.stream.Stream;
import lombok.Getter;

/**
 * The MATCHER_PROTECTION constants are flags in a bit field represented as a 16 bit long integer.
 * They describe the method an authenticator uses to protect the matcher that performs user
 * verification. These constants are reported and queried through the UAF Discovery APIs and used to
 * form authenticator policies in UAF protocol messages. Refer to [UAFAuthnrCommands] for more
 * details on the matcher component. Each constant has a case-sensitive string representation (in
 * quotes), which is used in the authoritative metadata for FIDO authenticators.
 *
 * @see #fromValue(int)
 * @see #fromName(String)
 * @see <a
 *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#matcher-protection-types">FIDO
 *     Registry of Predefined Values §3.3 Matcher Protection Types</a>
 */
@Getter
public enum MatcherProtectionType {

  /**
   * This flag MUST be set if the authenticator's matcher is running in software. Exclusive in
   * authenticator metadata with {@link #MATCHER_PROTECTION_TEE}, {@link
   * #MATCHER_PROTECTION_ON_CHIP}.
   *
   * <p>NOTE: The above requirements apply to authenticators; this library DOES NOT enforce them.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#matcher-protection-types">FIDO
   *     Registry of Predefined Values §3.3 Matcher Protection Types</a>
   */
  MATCHER_PROTECTION_SOFTWARE((short) 0x0001, "software"),

  /**
   * This flag SHOULD be set if the authenticator's matcher is running inside the Trusted Execution
   * Environment [TEE]. Mutually exclusive in authenticator metadata with {@link
   * #MATCHER_PROTECTION_SOFTWARE}, {@link #MATCHER_PROTECTION_ON_CHIP}.
   *
   * <p>NOTE: The above requirements apply to authenticators; this library DOES NOT enforce them.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#matcher-protection-types">FIDO
   *     Registry of Predefined Values §3.3 Matcher Protection Types</a>
   */
  MATCHER_PROTECTION_TEE((short) 0x0002, "tee"),

  /**
   * This flag SHOULD be set if the authenticator's matcher is running on the chip. Mutually
   * exclusive in authenticator metadata with {@link #MATCHER_PROTECTION_TEE}, {@link
   * #MATCHER_PROTECTION_SOFTWARE}
   *
   * <p>NOTE: The above requirements apply to authenticators; this library DOES NOT enforce them.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#matcher-protection-types">FIDO
   *     Registry of Predefined Values §3.3 Matcher Protection Types</a>
   */
  MATCHER_PROTECTION_ON_CHIP((short) 0x0004, "on_chip");

  private final short value;

  @JsonValue private final String name;

  MatcherProtectionType(short value, String name) {
    this.value = value;
    this.name = name;
  }

  /**
   * @return If <code>value</code> matches any {@link MatcherProtectionType} constant, returns that
   *     constant instance. Otherwise throws {@link IllegalArgumentException}.
   */
  public static MatcherProtectionType fromValue(int value) {
    return Stream.of(values())
        .filter(v -> v.value == value)
        .findAny()
        .orElseThrow(
            () ->
                new IllegalArgumentException(
                    String.format("Unknown %s value: 0x%04x", MatcherProtectionType.class, value)));
  }

  /**
   * @return If <code>name</code> matches any {@link MatcherProtectionType} constant, returns that
   *     constant instance. Otherwise throws {@link IllegalArgumentException}.
   */
  @JsonCreator
  public static MatcherProtectionType fromName(String name) {
    return Stream.of(values())
        .filter(v -> v.name.equals(name))
        .findAny()
        .orElseThrow(
            () ->
                new IllegalArgumentException(
                    String.format("Unknown %s name: %s", MatcherProtectionType.class, name)));
  }
}
