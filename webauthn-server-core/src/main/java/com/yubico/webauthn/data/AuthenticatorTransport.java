package com.yubico.webauthn.data;


import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import com.yubico.internal.util.json.JsonStringSerializable;
import com.yubico.internal.util.json.JsonStringSerializer;
import java.util.Optional;
import java.util.stream.Stream;
import lombok.AllArgsConstructor;
import lombok.NonNull;

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
@JsonSerialize(using = JsonStringSerializer.class)
@AllArgsConstructor
public enum AuthenticatorTransport implements JsonStringSerializable {
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

    @NonNull
    private final String id;

    private static Optional<AuthenticatorTransport> fromString(@NonNull String id) {
        return Stream.of(values()).filter(v -> v.id.equals(id)).findAny();
    }

    @JsonCreator
    private static AuthenticatorTransport fromJsonString(@NonNull String id) {
        return fromString(id).orElseThrow(() -> new IllegalArgumentException(String.format(
            "Unknown %s value: %s", AuthenticatorTransport.class.getSimpleName(), id
        )));
    }

    @Override
    public String toJsonString() {
        return id;
    }

}
