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
 * A WebAuthn Relying Party may require <a
 * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#user-verification">user
 * verification</a> for some of its operations but not for others, and may use this type to express
 * its needs.
 *
 * @see <a
 *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#enumdef-userverificationrequirement">§5.10.6.
 *     User Verification Requirement Enumeration (enum UserVerificationRequirement)</a>
 */
@JsonSerialize(using = JsonStringSerializer.class)
@AllArgsConstructor
public enum UserVerificationRequirement implements JsonStringSerializable {

  /**
   * This value indicates that the Relying Party does not want user verification employed during the
   * operation (e.g., in the interest of minimizing disruption to the user interaction flow).
   */
  DISCOURAGED("discouraged"),

  /**
   * This value indicates that the Relying Party prefers user verification for the operation if
   * possible, but will not fail the operation if the response does not have the {@link
   * AuthenticatorDataFlags#UV} flag set.
   */
  PREFERRED("preferred"),

  /**
   * Indicates that the Relying Party requires user verification for the operation and will fail the
   * operation if the response does not have the {@link AuthenticatorDataFlags#UV} flag set.
   */
  REQUIRED("required");

  @NonNull private final String id;

  private static Optional<UserVerificationRequirement> fromString(@NonNull String id) {
    return Stream.of(values()).filter(v -> v.id.equals(id)).findAny();
  }

  @JsonCreator
  private static UserVerificationRequirement fromJsonString(@NonNull String id) {
    return fromString(id)
        .orElseThrow(
            () ->
                new IllegalArgumentException(
                    String.format(
                        "Unknown %s value: %s",
                        UserVerificationRequirement.class.getSimpleName(), id)));
  }

  @Override
  public String toJsonString() {
    return id;
  }
}
