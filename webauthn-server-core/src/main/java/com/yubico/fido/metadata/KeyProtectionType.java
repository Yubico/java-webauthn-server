package com.yubico.fido.metadata;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;
import java.security.Key;
import java.util.stream.Stream;
import lombok.Getter;

/**
 * The KEY_PROTECTION constants are flags in a bit field represented as a 16 bit long integer. They
 * describe the method an authenticator uses to protect the private key material for FIDO
 * registrations. Refer to [UAFAuthnrCommands] for more details on the relevance of keys and key
 * protection. These constants are reported and queried through the UAF Discovery APIs and used to
 * form authenticator policies in UAF protocol messages. Each constant has a case-sensitive string
 * representation (in quotes), which is used in the authoritative metadata for FIDO authenticators.
 *
 * @see #fromValue(short)
 * @see #fromName(String)
 * @see <a
 *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#key-protection-types">FIDO
 *     Registry of Predefined Values §3.2 Key Protection Types</a>
 */
@Getter
public enum KeyProtectionType {

  /**
   * This flag MUST be set if the authenticator uses software-based key management. Exclusive in
   * authenticator metadata with {@link #KEY_PROTECTION_HARDWARE}, {@link #KEY_PROTECTION_TEE},
   * {@link #KEY_PROTECTION_SECURE_ELEMENT}.
   *
   * <p>NOTE: The above requirements apply to authenticators; this library DOES NOT enforce them.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#key-protection-types">FIDO
   *     Registry of Predefined Values §3.2 Key Protection Types</a>
   */
  KEY_PROTECTION_SOFTWARE((short) 0x0001, "software"),

  /**
   * This flag SHOULD be set if the authenticator uses hardware-based key management. Exclusive in
   * authenticator metadata with {@link #KEY_PROTECTION_SOFTWARE}.
   *
   * <p>NOTE: The above requirements apply to authenticators; this library DOES NOT enforce them.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#key-protection-types">FIDO
   *     Registry of Predefined Values §3.2 Key Protection Types</a>
   */
  KEY_PROTECTION_HARDWARE((short) 0x0002, "hardware"),

  /**
   * This flag SHOULD be set if the authenticator uses the Trusted Execution Environment [TEE] for
   * key management. In authenticator metadata, this flag should be set in conjunction with {@link
   * #KEY_PROTECTION_HARDWARE}. Mutually exclusive in authenticator metadata with {@link
   * #KEY_PROTECTION_SOFTWARE}, {@link #KEY_PROTECTION_SECURE_ELEMENT}.
   *
   * <p>NOTE: The above requirements apply to authenticators; this library DOES NOT enforce them.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#key-protection-types">FIDO
   *     Registry of Predefined Values §3.2 Key Protection Types</a>
   */
  KEY_PROTECTION_TEE((short) 0x0004, "tee"),

  /**
   * This flag SHOULD be set if the authenticator uses a Secure Element [SecureElement] for key
   * management. In authenticator metadata, this flag should be set in conjunction with {@link
   * #KEY_PROTECTION_HARDWARE}. Mutually exclusive in authenticator metadata with {@link
   * #KEY_PROTECTION_TEE}, {@link #KEY_PROTECTION_SOFTWARE}.
   *
   * <p>NOTE: The above requirements apply to authenticators; this library DOES NOT enforce them.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#key-protection-types">FIDO
   *     Registry of Predefined Values §3.2 Key Protection Types</a>
   */
  KEY_PROTECTION_SECURE_ELEMENT((short) 0x0008, "secure_element"),

  /**
   * This flag MUST be set if the authenticator does not store (wrapped) UAuth keys at the client,
   * but relies on a server-provided key handle. This flag MUST be set in conjunction with one of
   * the other KEY_PROTECTION flags to indicate how the local key handle wrapping key and operations
   * are protected. Servers MAY unset this flag in authenticator policy if they are not prepared to
   * store and return key handles, for example, if they have a requirement to respond
   * indistinguishably to authentication attempts against userIDs that do and do not exist. Refer to
   * [<a
   * href="https://fidoalliance.org/specs/fido-uaf-v1.2-rd-20171128/fido-uaf-protocol-v1.2-rd-20171128.html">UAFProtocol</a>]
   * for more details.
   *
   * <p>NOTE: The above requirements apply to authenticators; this library DOES NOT enforce them.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.1-ps-20191217.html#key-protection-types">FIDO
   *     Registry of Predefined Values §3.2 Key Protection Types</a>
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-uaf-v1.2-rd-20171128/fido-uaf-protocol-v1.2-rd-20171128.html">FIDO
   *     UAF Protocol Specification [UAFProtocol]</a>
   */
  KEY_PROTECTION_REMOTE_HANDLE((short) 0x0010, "remote_handle");

  private final short value;

  @JsonValue private final String name;

  KeyProtectionType(short value, String name) {
    this.value = value;
    this.name = name;
  }

  /**
   * @return If <code>value</code> matches any {@link KeyProtectionType} constant, returns that
   *     constant instance. Otherwise throws {@link IllegalArgumentException}.
   */
  public static KeyProtectionType fromValue(short value) {
    return Stream.of(values())
        .filter(v -> v.value == value)
        .findAny()
        .orElseThrow(
            () ->
                new IllegalArgumentException(
                    String.format("Unknown %s value: 0x%04x", KeyProtectionType.class, value)));
  }

  /**
   * @return If <code>name</code> matches any {@link Key} constant, returns that constant instance.
   *     Otherwise throws {@link IllegalArgumentException}.
   */
  @JsonCreator
  public static KeyProtectionType fromName(String name) {
    return Stream.of(values())
        .filter(v -> v.name.equals(name))
        .findAny()
        .orElseThrow(
            () ->
                new IllegalArgumentException(
                    String.format("Unknown %s name: %s", KeyProtectionType.class, name)));
  }
}
