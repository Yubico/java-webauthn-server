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
import com.fasterxml.jackson.annotation.JsonValue;
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
@Value
@AllArgsConstructor(access = AccessLevel.PRIVATE)
public class PublicKeyCredentialHint {

  @JsonValue @NonNull private final String value;

  public static final PublicKeyCredentialHint SECURITY_KEY =
      new PublicKeyCredentialHint("security-key");

  public static final PublicKeyCredentialHint CLIENT_DEVICE =
      new PublicKeyCredentialHint("client-device");

  public static final PublicKeyCredentialHint HYBRID = new PublicKeyCredentialHint("hybrid");

  /**
   * @return An array containing all predefined values of {@link PublicKeyCredentialHint} known by
   *     this implementation.
   */
  public static PublicKeyCredentialHint[] values() {
    return new PublicKeyCredentialHint[] {SECURITY_KEY, CLIENT_DEVICE, HYBRID};
  }

  /**
   * @return If <code>value</code> is the same as that of any of {@link #SECURITY_KEY}, {@link
   *     #CLIENT_DEVICE} or {@link #HYBRID}, returns that constant instance. Otherwise returns a new
   *     instance containing <code>value</code>.
   * @see #valueOf(String)
   */
  @JsonCreator
  public static PublicKeyCredentialHint of(@NonNull String value) {
    return Stream.of(values())
        .filter(v -> v.getValue().equals(value))
        .findAny()
        .orElseGet(() -> new PublicKeyCredentialHint(value));
  }

  /**
   * @return If <code>name</code> equals <code>"SECURITY_KEY"</code>, <code>"CLIENT_DEVICE"</code>
   *     or <code>"HYBRID"</code>, returns the constant by that name.
   * @throws IllegalArgumentException if <code>name</code> is anything else.
   * @see #of(String)
   */
  public static PublicKeyCredentialHint valueOf(String name) {
    switch (name) {
      case "SECURITY_KEY":
        return SECURITY_KEY;
      case "CLIENT_DEVICE":
        return CLIENT_DEVICE;
      case "HYBRID":
        return HYBRID;
      default:
        throw new IllegalArgumentException(
            "No constant com.yubico.webauthn.data.PublicKeyCredentialHint." + name);
    }
  }
}
