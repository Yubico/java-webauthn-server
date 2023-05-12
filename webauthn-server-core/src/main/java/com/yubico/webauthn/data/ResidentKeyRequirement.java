// Copyright (c) 2021, Yubico AB
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
import java.util.Optional;
import java.util.stream.Stream;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NonNull;

/**
 * This enumeration's values describe the Relying Party's requirements for client-side discoverable
 * credentials, also known as <i>passkeys</i> (formerly known as resident credentials or resident
 * keys).
 *
 * @see <a
 *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#enum-residentKeyRequirement">§5.4.6.
 *     Resident Key Requirement Enumeration (enum ResidentKeyRequirement)</a>
 * @see <a
 *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#client-side-discoverable-credential">Client-side
 *     discoverable Credential</a>
 * @see <a href="https://passkeys.dev/docs/reference/terms/#passkey">Passkey</a>
 */
@AllArgsConstructor
public enum ResidentKeyRequirement {

  /**
   * The client and authenticator will try to create a server-side credential if possible, and a
   * discoverable credential (passkey) otherwise.
   *
   * @see <a
   *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#enum-residentKeyRequirement">§5.4.6.
   *     Resident Key Requirement Enumeration (enum ResidentKeyRequirement)</a>
   * @see <a
   *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#client-side-discoverable-credential">Client-side
   *     discoverable Credential</a>
   * @see <a
   *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#server-side-credential">Server-side
   *     Credential</a>
   * @see <a href="https://passkeys.dev/docs/reference/terms/#passkey">Passkey</a>
   */
  DISCOURAGED("discouraged"),

  /**
   * The client and authenticator will try to create a discoverable credential (passkey) if
   * possible, and a server-side credential otherwise.
   *
   * @see <a
   *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#enum-residentKeyRequirement">§5.4.6.
   *     Resident Key Requirement Enumeration (enum ResidentKeyRequirement)</a>
   * @see <a
   *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#client-side-discoverable-credential">Client-side
   *     discoverable Credential</a>
   * @see <a
   *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#server-side-credential">Server-side
   *     Credential</a>
   * @see <a href="https://passkeys.dev/docs/reference/terms/#passkey">Passkey</a>
   */
  PREFERRED("preferred"),

  /**
   * The client and authenticator will try to create a discoverable credential (passkey), and fail
   * the registration if that is not possible.
   *
   * @see <a
   *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#enum-residentKeyRequirement">§5.4.6.
   *     Resident Key Requirement Enumeration (enum ResidentKeyRequirement)</a>
   * @see <a
   *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#client-side-discoverable-credential">Client-side
   *     discoverable Credential</a>
   * @see <a
   *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#server-side-credential">Server-side
   *     Credential</a>
   * @see <a href="https://passkeys.dev/docs/reference/terms/#passkey">Passkey</a>
   */
  REQUIRED("required");

  @JsonValue @Getter @NonNull private final String value;

  private static Optional<ResidentKeyRequirement> fromString(@NonNull String value) {
    return Stream.of(values()).filter(v -> v.value.equals(value)).findAny();
  }

  @JsonCreator
  private static ResidentKeyRequirement fromJsonString(@NonNull String value) {
    return fromString(value)
        .orElseThrow(
            () ->
                new IllegalArgumentException(
                    String.format(
                        "Unknown %s value: %s",
                        ResidentKeyRequirement.class.getSimpleName(), value)));
  }
}
