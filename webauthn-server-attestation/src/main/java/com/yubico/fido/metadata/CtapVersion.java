package com.yubico.fido.metadata;

/**
 * Enumeration of CTAP versions.
 *
 * @see <a
 *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetInfo">Client
 *     to Authenticator Protocol (CTAP) §6.4. authenticatorGetInfo (0x04)</a>
 */
public enum CtapVersion {

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetInfo">Client
   *     to Authenticator Protocol (CTAP) §6.4. authenticatorGetInfo (0x04)</a>
   */
  U2F_V2,

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetInfo">Client
   *     to Authenticator Protocol (CTAP) §6.4. authenticatorGetInfo (0x04)</a>
   */
  FIDO_2_0,

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetInfo">Client
   *     to Authenticator Protocol (CTAP) §6.4. authenticatorGetInfo (0x04)</a>
   */
  FIDO_2_1_PRE,

  /**
   * @see <a
   *     href="https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorGetInfo">Client
   *     to Authenticator Protocol (CTAP) §6.4. authenticatorGetInfo (0x04)</a>
   */
  FIDO_2_1;
}
