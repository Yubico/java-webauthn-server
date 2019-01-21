// Copyright (c) 2018, Yubico AB
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

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
 * Authenticators may communicate with Clients using a variety of transports. This enumeration defines a hint as to how
 * Clients might communicate with a particular Authenticator in order to obtain an assertion for a specific credential.
 * Note that these hints represent the Relying Party's best belief as to how an Authenticator may be reached. A Relying
 * Party may obtain a list of transports hints from some attestation statement formats or via some out-of-band
 * mechanism; it is outside the scope of this specification to define that mechanism.
 * <p>
 * Authenticators may implement various transports for communicating with clients. This enumeration defines hints as to
 * how clients might communicate with a particular authenticator in order to obtain an assertion for a specific
 * credential. Note that these hints represent the WebAuthn Relying Party's best belief as to how an authenticator may
 * be reached. A Relying Party may obtain a list of transports hints from some attestation statement formats or via some
 * out-of-band mechanism; it is outside the scope of the Web Authentication specification to define that mechanism.
 * </p>
 *
 * @see <a href="https://www.w3.org/TR/2019/PR-webauthn-20190117/#enumdef-authenticatortransport">§5.10.4. Authenticator
 * Transport Enumeration (enum AuthenticatorTransport)</a>
 */
@JsonSerialize(using = JsonStringSerializer.class)
@AllArgsConstructor
public enum AuthenticatorTransport implements JsonStringSerializable {

    /**
     * Indicates the respective authenticator can be contacted over removable USB.
     */
    USB("usb"),

    /**
     * Indicates the respective authenticator can be contacted over Near Field Communication (NFC).
     */
    NFC("nfc"),

    /**
     * Indicates the respective authenticator can be contacted over Bluetooth Smart (Bluetooth Low Energy / BLE).
     */
    BLE("ble"),

    /**
     * Indicates the respective authenticator is contacted using a client device-specific transport. These
     * authenticators are not removable from the client device.
     */
    INTERNAL("internal")
    ;

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
