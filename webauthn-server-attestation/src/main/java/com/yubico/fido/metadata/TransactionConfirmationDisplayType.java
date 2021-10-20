package com.yubico.fido.metadata;

import com.fasterxml.jackson.annotation.JsonValue;

/**
 * The TRANSACTION_CONFIRMATION_DISPLAY constants are flags in a bit field represented as a 16 bit
 * long integer. They describe the availability and implementation of a transaction confirmation
 * display capability required for the transaction confirmation operation. These constants are
 * reported and queried through the UAF Discovery APIs and used to form authenticator policies in
 * UAF protocol messages. Each constant has a case-sensitive string representation (in quotes),
 * which is used in the authoritative metadata for FIDO authenticators. Refer to [<a
 * href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#bib-UAFAuthnrCommands">UAFAuthnrCommands</a>]
 * for more details on the security aspects of TransactionConfirmation Display.
 *
 * @see <a
 *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#transaction-confirmation-display-types">FIDO
 *     Registry of Predefined Values §3.5 Transaction Confirmation Display Types</a>
 */
public enum TransactionConfirmationDisplayType {

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#transaction-confirmation-display-types">FIDO
   *     Registry of Predefined Values §3.5 Transaction Confirmation Display Types</a>
   */
  TRANSACTION_CONFIRMATION_DISPLAY_ANY(0x0001, "any"),

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#transaction-confirmation-display-types">FIDO
   *     Registry of Predefined Values §3.5 Transaction Confirmation Display Types</a>
   */
  TRANSACTION_CONFIRMATION_DISPLAY_PRIVILEGED_SOFTWARE(0x0002, "privileged_software"),

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#transaction-confirmation-display-types">FIDO
   *     Registry of Predefined Values §3.5 Transaction Confirmation Display Types</a>
   */
  TRANSACTION_CONFIRMATION_DISPLAY_TEE(0x0004, "tee"),

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#transaction-confirmation-display-types">FIDO
   *     Registry of Predefined Values §3.5 Transaction Confirmation Display Types</a>
   */
  TRANSACTION_CONFIRMATION_DISPLAY_HARDWARE(0x0008, "hardware"),

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/common-specs/fido-registry-v2.2-rd-20210525.html#transaction-confirmation-display-types">FIDO
   *     Registry of Predefined Values §3.5 Transaction Confirmation Display Types</a>
   */
  TRANSACTION_CONFIRMATION_DISPLAY_REMOTE(0x0010, "remote");

  private final int value;

  @JsonValue private final String name;

  TransactionConfirmationDisplayType(int value, String name) {
    this.value = value;
    this.name = name;
  }
}
