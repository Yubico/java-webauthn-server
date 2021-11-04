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
 * This enumeration’s values describe authenticators' <a
 * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#authenticator-attachment-modality">attachment
 * modalities</a>. Relying Parties use this for two purposes:
 *
 * <ul>
 *   <li>to express a preferred authenticator attachment modality when calling <code>
 *       navigator.credentials.create()</code> to create a credential, and
 *   <li>to inform the client of the Relying Party's best belief about how to locate the managing
 *       authenticators of the credentials listed in {@link
 *       PublicKeyCredentialRequestOptions#getAllowCredentials()} when calling <code>
 *       navigator.credentials.get()</code>.
 * </ul>
 *
 * @see <a
 *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#enumdef-authenticatorattachment">§5.4.5.
 *     Authenticator Attachment Enumeration (enum AuthenticatorAttachment) </a>
 */
@JsonSerialize(using = JsonStringSerializer.class)
@AllArgsConstructor
public enum AuthenticatorAttachment implements JsonStringSerializable {

  /**
   * Indicates <a
   * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#cross-platform-attachment">cross-platform
   * attachment</a>.
   *
   * <p>Authenticators of this class are removable from, and can "roam" among, client platforms.
   */
  CROSS_PLATFORM("cross-platform"),

  /**
   * Indicates <a
   * href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#platform-attachment">platform
   * attachment</a>.
   *
   * <p>Usually, authenticators of this class are not removable from the platform.
   */
  PLATFORM("platform");

  @NonNull private final String id;

  private static Optional<AuthenticatorAttachment> fromString(@NonNull String id) {
    return Stream.of(values()).filter(v -> v.id.equals(id)).findAny();
  }

  @JsonCreator
  private static AuthenticatorAttachment fromJsonString(@NonNull String id) {
    return fromString(id)
        .orElseThrow(
            () ->
                new IllegalArgumentException(
                    String.format(
                        "Unknown %s value: %s",
                        AuthenticatorAttachment.class.getSimpleName(), id)));
  }

  @Override
  public String toJsonString() {
    return id;
  }
}
