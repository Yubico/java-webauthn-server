package com.yubico.fido.metadata;

import com.fasterxml.jackson.annotation.JsonValue;

/**
 * The ATTACHMENT_HINT constants are flags in a bit field represented as a 32 bit long. They
 * describe the method FIDO authenticators use to communicate with the FIDO User Device. These
 * constants are reported and queried through the UAF Discovery APIs [UAFAppAPIAndTransport], and
 * used to form Authenticator policies in UAF protocol messages. Because the connection state and
 * topology of an authenticator may be transient, these values are only hints that can be used by
 * server-supplied policy to guide the user experience, e.g. to prefer a device that is connected
 * and ready for authenticating or confirming a low-value transaction, rather than one that is more
 * secure but requires more user effort. Each constant has a case-sensitive string representation
 * (in quotes), which is used in the authoritative metadata for FIDO authenticators. Note
 *
 * <p>These flags are not a mandatory part of authenticator metadata and, when present, only
 * indicate possible states that may be reported during authenticator discovery.
 *
 * @see <a
 *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#authenticator-attachment-hints">FIDO
 *     Registry of Predefined Values §3.4 Authenticator Attachment Hints</a>
 */
public enum AttachmentHint {

  /**
   * This flag MAY be set to indicate that the authenticator is permanently attached to the FIDO
   * User Device.
   *
   * <p>A device such as a smartphone may have authenticator functionality that is able to be used
   * both locally and remotely. In such a case, the FIDO client MUST filter and exclusively report
   * only the relevant bit during Discovery and when performing policy matching.
   *
   * <p>This flag cannot be combined with any other {@link AttachmentHint} flags.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#authenticator-attachment-hints">FIDO
   *     Registry of Predefined Values §3.4 Authenticator Attachment Hints</a>
   */
  ATTACHMENT_HINT_INTERNAL(0x0001, "internal"),

  /**
   * This flag MAY be set to indicate, for a hardware-based authenticator, that it is removable or
   * remote from the FIDO User Device.
   *
   * <p>A device such as a smartphone may have authenticator functionality that is able to be used
   * both locally and remotely. In such a case, the FIDO UAF Client MUST filter and exclusively
   * report only the relevant bit during discovery and when performing policy matching. This flag
   * MUST be combined with one or more other {@link AttachmentHint} flag(s).
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#authenticator-attachment-hints">FIDO
   *     Registry of Predefined Values §3.4 Authenticator Attachment Hints</a>
   */
  ATTACHMENT_HINT_EXTERNAL(0x0002, "external"),

  /**
   * This flag MAY be set to indicate that an external authenticator currently has an exclusive
   * wired connection, e.g. through USB, Firewire or similar, to the FIDO User Device.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#authenticator-attachment-hints">FIDO
   *     Registry of Predefined Values §3.4 Authenticator Attachment Hints</a>
   */
  ATTACHMENT_HINT_WIRED(0x0004, "wired"),

  /**
   * This flag MAY be set to indicate that an external authenticator communicates with the FIDO User
   * Device through a personal area or otherwise non-routed wireless protocol, such as Bluetooth or
   * NFC.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#authenticator-attachment-hints">FIDO
   *     Registry of Predefined Values §3.4 Authenticator Attachment Hints</a>
   */
  ATTACHMENT_HINT_WIRELESS(0x0008, "wireless"),

  /**
   * This flag MAY be set to indicate that an external authenticator is able to communicate by NFC
   * to the FIDO User Device. As part of authenticator metadata, or when reporting characteristics
   * through discovery, if this flag is set, the {@link #ATTACHMENT_HINT_WIRELESS} flag SHOULD also
   * be set as well.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#authenticator-attachment-hints">FIDO
   *     Registry of Predefined Values §3.4 Authenticator Attachment Hints</a>
   */
  ATTACHMENT_HINT_NFC(0x0010, "nfc"),

  /**
   * This flag MAY be set to indicate that an external authenticator is able to communicate using
   * Bluetooth with the FIDO User Device. As part of authenticator metadata, or when reporting
   * characteristics through discovery, if this flag is set, the {@link #ATTACHMENT_HINT_WIRELESS}
   * flag SHOULD also be set.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#authenticator-attachment-hints">FIDO
   *     Registry of Predefined Values §3.4 Authenticator Attachment Hints</a>
   */
  ATTACHMENT_HINT_BLUETOOTH(0x0020, "bluetooth"),

  /**
   * This flag MAY be set to indicate that the authenticator is connected to the FIDO User Device
   * over a non-exclusive network (e.g. over a TCP/IP LAN or WAN, as opposed to a PAN or
   * point-to-point connection).
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#authenticator-attachment-hints">FIDO
   *     Registry of Predefined Values §3.4 Authenticator Attachment Hints</a>
   */
  ATTACHMENT_HINT_NETWORK(0x0040, "network"),

  /**
   * This flag MAY be set to indicate that an external authenticator is in a "ready" state. This
   * flag is set by the ASM at its discretion.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#authenticator-attachment-hints">FIDO
   *     Registry of Predefined Values §3.4 Authenticator Attachment Hints</a>
   */
  ATTACHMENT_HINT_READY(0x0080, "ready"),

  /**
   * This flag MAY be set to indicate that an external authenticator is able to communicate using
   * WiFi Direct with the FIDO User Device. As part of authenticator metadata and when reporting
   * characteristics through discovery, if this flag is set, the {@link #ATTACHMENT_HINT_WIRELESS}
   * flag SHOULD also be set.
   *
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#authenticator-attachment-hints">FIDO
   *     Registry of Predefined Values §3.4 Authenticator Attachment Hints</a>
   */
  ATTACHMENT_HINT_WIFI_DIRECT(0x0100, "wifi_direct");

  private final int value;

  @JsonValue private final String name;

  AttachmentHint(int value, String name) {
    this.value = value;
    this.name = name;
  }
}
