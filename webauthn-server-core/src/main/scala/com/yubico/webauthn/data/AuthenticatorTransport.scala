package com.yubico.webauthn.data

import java.util.Optional

import com.yubico.scala.util.JavaConverters._


/**
  * Authenticators may communicate with Clients using a variety of transports.
  * This enumeration defines a hint as to how Clients might communicate with a
  * particular Authenticator in order to obtain an assertion for a specific
  * credential. Note that these hints represent the Relying Party's best belief
  * as to how an Authenticator may be reached. A Relying Party may obtain a list
  * of transports hints from some attestation statement formats or via some
  * out-of-band mechanism; it is outside the scope of this specification to
  * define that mechanism.
  */
object AuthenticatorTransport {
  def apply(id: String): Optional[AuthenticatorTransport] = List(USB, NFC, BLE).find(_.id == id).asJava
}

sealed trait AuthenticatorTransport {
  def id: String
}

/**
  * The respective Authenticator may be contacted over USB.
  */
case object USB extends AuthenticatorTransport { override def id = "usb" }

/**
  * The respective Authenticator may be contacted over Near Field Communication
  * (NFC).
  */
case object NFC extends AuthenticatorTransport { override def id = "nfc" }

/**
  * The respective Authenticator may be contacted over Bluetooth Smart
  * (Bluetooth Low Energy / BLE).
  */
case object BLE extends AuthenticatorTransport { override def id = "ble" }
