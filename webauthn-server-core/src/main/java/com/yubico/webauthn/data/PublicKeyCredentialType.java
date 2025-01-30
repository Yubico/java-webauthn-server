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
import java.util.Optional;
import java.util.stream.Stream;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NonNull;

/**
 * Defines the valid credential types.
 *
 * <p>It is an extensions point; values may be added to it in the future, as more credential types
 * are defined. The values of this enumeration are used for versioning the Authentication Assertion
 * and attestation structures according to the type of the authenticator.
 *
 * <p>Currently one credential type is defined, namely {@link #PUBLIC_KEY}.
 *
 * @see <a
 *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#enumdef-publickeycredentialtype">§5.10.2.
 *     Credential Type Enumeration (enum PublicKeyCredentialType)</a>
 */
@AllArgsConstructor
public enum PublicKeyCredentialType {
  PUBLIC_KEY("public-key");

  @JsonValue @Getter @NonNull private final String id;

  /**
   * Attempt to parse a string as a {@link PublicKeyCredentialType}.
   *
   * @param id a {@link String} equal to the {@link #getId() id} of a constant in {@link
   *     PublicKeyCredentialType}
   * @return The {@link AuthenticatorAttachment} instance whose {@link #getId() id} equals <code>id
   *     </code>, if any.
   * @see <a
   *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#enumdef-publickeycredentialtype">§5.10.2.
   *     Credential Type Enumeration (enum PublicKeyCredentialType)</a>
   */
  public static Optional<PublicKeyCredentialType> fromId(@NonNull String id) {
    return Stream.of(values()).filter(v -> v.id.equals(id)).findAny();
  }

  @JsonCreator
  private static PublicKeyCredentialType fromJsonString(@NonNull String id) {
    return fromId(id)
        .orElseThrow(
            () ->
                new IllegalArgumentException(
                    String.format(
                        "Unknown %s value: %s",
                        PublicKeyCredentialType.class.getSimpleName(), id)));
  }
}
