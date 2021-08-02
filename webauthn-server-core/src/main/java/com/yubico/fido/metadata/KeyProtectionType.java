package com.yubico.fido.metadata;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import java.util.stream.Stream;
import lombok.EqualsAndHashCode;

/**
 * Enum-like collection of known <code>KEY_PROTECTION</code> values.
 *
 * <p>Constants in this class behave like enum constants. Use {@link #of(short)} to parse raw <code>
 * int</code> values.
 *
 * @see #of(short)
 * @see <a
 *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#key-protection-types">FIDO
 *     Registry of Predefined Values §3.2 Key Protection Types</a>
 */
@EqualsAndHashCode
public class KeyProtectionType {

  /**
   * This flag must be set if the authenticator uses software-based key management. Mutually
   * exclusive with {@link #KEY_PROTECTION_HARDWARE}, {@link #KEY_PROTECTION_TEE}, {@link
   * #KEY_PROTECTION_SECURE_ELEMENT}.
   *
   * <p>NOTE: The above requirements apply to authenticators; this library DOES NOT enforce them.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#key-protection-types">FIDO
   *     Registry of Predefined Values §3.2 Key Protection Types</a>
   */
  public static final KeyProtectionType KEY_PROTECTION_SOFTWARE =
      new KeyProtectionType((short) 0x0001, "SOFTWARE");

  /**
   * This flag should be set if the authenticator uses hardware-based key management. Mutually
   * exclusive with {@link #KEY_PROTECTION_SOFTWARE}.
   *
   * <p>NOTE: The above requirements apply to authenticators; this library DOES NOT enforce them.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#key-protection-types">FIDO
   *     Registry of Predefined Values §3.2 Key Protection Types</a>
   */
  public static final KeyProtectionType KEY_PROTECTION_HARDWARE =
      new KeyProtectionType((short) 0x0002, "HARDWARE");

  /**
   * This flag should be set if the authenticator uses the Trusted Execution Environment for key
   * management. In authenticator metadata, this flag should be set in conjunction with {@link
   * #KEY_PROTECTION_HARDWARE}. Mutually exclusive with {@link #KEY_PROTECTION_SOFTWARE}, {@link
   * #KEY_PROTECTION_SECURE_ELEMENT}.
   *
   * <p>NOTE: The above requirements apply to authenticators; this library DOES NOT enforce them.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#key-protection-types">FIDO
   *     Registry of Predefined Values §3.2 Key Protection Types</a>
   */
  public static final KeyProtectionType KEY_PROTECTION_TEE =
      new KeyProtectionType((short) 0x0004, "TEE");

  /**
   * This flag should be set if the authenticator uses a Secure Element for key management. In
   * authenticator metadata, this flag should be set in conjunction with {@link
   * #KEY_PROTECTION_HARDWARE}. Mutually exclusive with {@link #KEY_PROTECTION_TEE}, {@link
   * #KEY_PROTECTION_SOFTWARE}.
   *
   * <p>NOTE: The above requirements apply to authenticators; this library DOES NOT enforce them.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#key-protection-types">FIDO
   *     Registry of Predefined Values §3.2 Key Protection Types</a>
   */
  public static final KeyProtectionType KEY_PROTECTION_SECURE_ELEMENT =
      new KeyProtectionType((short) 0x0008, "SECURE_ELEMENT");

  /**
   * This flag must be set if the authenticator does not store (wrapped) UAuth keys at the client,
   * but relies on a server-provided key handle. This flag must be set in conjunction with one of
   * the other KEY_PROTECTION flags to indicate how the local key handle wrapping key and operations
   * are protected. Servers may unset this flag in authenticator policy if they are not prepared to
   * store and return key handles, for example, if they have a requirement to respond
   * indistinguishably to authentication attempts against userIDs that do and do not exist. Refer to
   * [UAFProtocol] for more details.
   *
   * <p>NOTE: The above requirements apply to authenticators; this library DOES NOT enforce them.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-registry-v2.0-id-20180227.html#key-protection-types">FIDO
   *     Registry of Predefined Values §3.2 Key Protection Types</a>
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-uaf-v1.2-rd-20171128/fido-uaf-protocol-v1.2-rd-20171128.html">FIDO
   *     UAF Protocol Specification [UAFProtocol]</a>
   */
  public static final KeyProtectionType KEY_PROTECTION_REMOTE_HANDLE =
      new KeyProtectionType((short) 0x0010, "REMOTE_HANDLE");

  @JsonValue public final short value;

  @EqualsAndHashCode.Exclude private final transient String name;

  private KeyProtectionType(short value, String name) {
    this.value = value;
    this.name = name;
  }

  /**
   * @return An array containing all predefined values of {@link KeyProtectionType} known by this
   *     implementation.
   */
  public static KeyProtectionType[] values() {
    return new KeyProtectionType[] {
      KEY_PROTECTION_SOFTWARE,
      KEY_PROTECTION_HARDWARE,
      KEY_PROTECTION_TEE,
      KEY_PROTECTION_SECURE_ELEMENT,
      KEY_PROTECTION_REMOTE_HANDLE
    };
  }

  /**
   * @return If <code>value</code> is the same as that of any of the constants in {@link
   *     KeyProtectionType}, returns that constant instance. Otherwise returns a new instance
   *     containing <code>value</code>.
   */
  @JsonCreator
  public static KeyProtectionType of(short value) {
    return Stream.of(values())
        .filter(v -> v.value == value)
        .findAny()
        .orElseGet(() -> new KeyProtectionType(value, null));
  }

  @Override
  public String toString() {
    if (name == null) {
      return String.format("%s(%04x)", KeyProtectionType.class.getSimpleName(), value);
    } else {
      return "KEY_PROTECTION_" + name;
    }
  }
}
