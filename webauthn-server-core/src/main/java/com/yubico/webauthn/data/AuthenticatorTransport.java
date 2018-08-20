package com.yubico.webauthn.data;


import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.yubico.webauthn.impl.json.StringIdJsonSerializer;
import com.yubico.webauthn.impl.json.WithStringId;
import lombok.AllArgsConstructor;
import lombok.Getter;

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
@JsonSerialize(using = StringIdJsonSerializer.class)
@AllArgsConstructor
public enum AuthenticatorTransport implements WithStringId {
    /**
     * The respective Authenticator may be contacted over USB.
     */
    USB("usb"),

    /**
     * The respective Authenticator may be contacted over Near Field Communication
     * (NFC).
     */
    NFC("nfc"),

    /**
     * The respective Authenticator may be contacted over Bluetooth Smart
     * (Bluetooth Low Energy / BLE).
     */
    BLE("ble");

    @Getter
    private final String id;

}

