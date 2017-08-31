package com.yubico.webauthn.data.impl

case class AuthenticationDataFlags(value: Byte) {
  /** User present */
  def UP: Boolean = (value & 0x01) > 0

  /** User verified */
  def UV: Boolean = (value & 0x04) > 0

  /** Attestation data present */
  def AT: Boolean = (value & 0x40) > 0

  /** Extension data present */
  def ED: Boolean = (value & 0x80) > 0

  /* Reserved bits */
  // def RFU1: Boolean = (value & 0x02) > 0
  // def RFU2_1: Boolean = (value & 0x08) > 0
  // def RFU2_2: Boolean = (value & 0x10) > 0
  // def RFU2_3: Boolean = (value & 0x20) > 0
}
