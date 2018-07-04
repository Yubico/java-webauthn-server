package com.yubico.webauthn.data;


import com.fasterxml.jackson.core.JsonGenerator;
import com.fasterxml.jackson.databind.SerializerProvider;
import com.fasterxml.jackson.databind.annotation.JsonSerialize;
import java.io.IOException;

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
@JsonSerialize(using = AuthenticatorTransport.JsonSerializer.class)
public enum AuthenticatorTransport {
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

    private String id;

    AuthenticatorTransport(String id) {
        this.id = id;
    }

    static class JsonSerializer extends com.fasterxml.jackson.databind.JsonSerializer<AuthenticatorTransport> {
        @Override
        public void serialize(AuthenticatorTransport t, JsonGenerator jsonGenerator, SerializerProvider serializerProvider) throws IOException {
            jsonGenerator.writeString(t.id);
        }
    }
}

