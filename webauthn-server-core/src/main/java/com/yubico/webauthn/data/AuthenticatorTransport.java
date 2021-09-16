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
import com.yubico.webauthn.attestation.Transport;
import java.util.stream.Stream;
import lombok.AccessLevel;
import lombok.AllArgsConstructor;
import lombok.NonNull;
import lombok.Value;

/**
 * Authenticators may communicate with Clients using a variety of transports. This enumeration
 * defines a hint as to how Clients might communicate with a particular Authenticator in order to
 * obtain an assertion for a specific credential. Note that these hints represent the Relying
 * Party's best belief as to how an Authenticator may be reached. A Relying Party may obtain a list
 * of transports hints from some attestation statement formats or via some out-of-band mechanism; it
 * is outside the scope of this specification to define that mechanism.
 *
 * <p>Authenticators may implement various transports for communicating with clients. This
 * enumeration defines hints as to how clients might communicate with a particular authenticator in
 * order to obtain an assertion for a specific credential. Note that these hints represent the
 * WebAuthn Relying Party's best belief as to how an authenticator may be reached. A Relying Party
 * may obtain a list of transports hints from some attestation statement formats or via some
 * out-of-band mechanism; it is outside the scope of the Web Authentication specification to define
 * that mechanism.
 *
 * @see <a
 *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#enumdef-authenticatortransport">§5.10.4.
 *     Authenticator Transport Enumeration (enum AuthenticatorTransport)</a>
 */
@JsonSerialize(using = JsonStringSerializer.class)
@Value
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class AuthenticatorTransport
    implements Comparable<AuthenticatorTransport>, JsonStringSerializable {

  @NonNull private final String id;

  /** Indicates the respective authenticator can be contacted over removable USB. */
  public static final AuthenticatorTransport USB = new AuthenticatorTransport("usb");

  /**
   * Indicates the respective authenticator can be contacted over Near Field Communication (NFC).
   */
  public static final AuthenticatorTransport NFC = new AuthenticatorTransport("nfc");

  /**
   * Indicates the respective authenticator can be contacted over Bluetooth Smart (Bluetooth Low
   * Energy / BLE).
   */
  public static final AuthenticatorTransport BLE = new AuthenticatorTransport("ble");

  /**
   * Indicates the respective authenticator is contacted using a client device-specific transport.
   * These authenticators are not removable from the client device.
   */
  public static final AuthenticatorTransport INTERNAL = new AuthenticatorTransport("internal");

  /**
   * @return An array containing all predefined values of {@link AuthenticatorTransport} known by
   *     this implementation.
   */
  public static AuthenticatorTransport[] values() {
    return new AuthenticatorTransport[] {USB, NFC, BLE, INTERNAL};
  }

  /**
   * @return If <code>id</code> is the same as that of any of {@link #USB}, {@link #NFC}, {@link
   *     #BLE} or {@link #INTERNAL}, returns that constant instance. Otherwise returns a new
   *     instance containing <code>id</code>.
   * @see #valueOf(String)
   */
  @JsonCreator
  public static AuthenticatorTransport of(@NonNull String id) {
    return Stream.of(values())
        .filter(v -> v.getId().equals(id))
        .findAny()
        .orElseGet(() -> new AuthenticatorTransport(id));
  }

  /**
   * @return If <code>name</code> equals <code>"USB"</code>, <code>"NFC"</code>, <code>"BLE"</code>
   *     or <code>"INTERNAL"</code>, returns the constant by that name.
   * @throws IllegalArgumentException if <code>name</code> is anything else.
   * @see #of(String)
   */
  public static AuthenticatorTransport valueOf(String name) {
    switch (name) {
      case "USB":
        return USB;
      case "NFC":
        return NFC;
      case "BLE":
        return BLE;
      case "INTERNAL":
        return INTERNAL;
      default:
        throw new IllegalArgumentException(
            "No constant com.yubico.webauthn.data.AuthenticatorTransport." + name);
    }
  }

  /**
   * Convert a {@link Transport} from U2F metadata to a WebAuthn {@link AuthenticatorTransport}
   * value.
   *
   * @throws IllegalArgumentException if <code>transport</code> has an unknown value.
   */
  public static AuthenticatorTransport fromU2fTransport(Transport transport) {
    switch (transport) {
      case BT_CLASSIC:
      case BLE:
        return BLE;

      case USB:
      case LIGHTNING:
        return USB;

      case NFC:
        return NFC;

      default:
        throw new IllegalArgumentException("Unknown transport: " + transport);
    }
  }

  @Override
  public String toJsonString() {
    return id;
  }

  @Override
  public int compareTo(AuthenticatorTransport other) {
    return id.compareTo(other.id);
  }
}
