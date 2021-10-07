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

import static com.yubico.internal.util.ExceptionUtil.assure;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import java.util.Optional;
import lombok.NonNull;
import lombok.Value;

/**
 * Information about the state of the <a href="https://tools.ietf.org/html/rfc8471">Token Binding
 * protocol</a> used when communicating with the Relying Party.
 *
 * @see <a
 *     href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#dictdef-tokenbinding">dictionary
 *     TokenBinding</a>
 */
@Value
public class TokenBindingInfo {

  @NonNull private final TokenBindingStatus status;

  /**
   * This member MUST be present if {@link #status} is {@link TokenBindingStatus#PRESENT PRESENT},
   * and MUST be the Token Binding ID that was used when communicating with the Relying Party.
   */
  private final ByteArray id;

  @JsonCreator
  TokenBindingInfo(
      @NonNull @JsonProperty("status") TokenBindingStatus status,
      @NonNull @JsonProperty("id") Optional<ByteArray> id) {
    if (status == TokenBindingStatus.PRESENT) {
      assure(
          id.isPresent(),
          "Token binding ID must be present if status is \"%s\".",
          TokenBindingStatus.PRESENT);
    } else {
      assure(
          !id.isPresent(),
          "Token binding ID must not be present if status is not \"%s\".",
          TokenBindingStatus.PRESENT);
    }

    this.status = status;
    this.id = id.orElse(null);
  }

  public static TokenBindingInfo present(@NonNull ByteArray id) {
    return new TokenBindingInfo(TokenBindingStatus.PRESENT, Optional.of(id));
  }

  public static TokenBindingInfo supported() {
    return new TokenBindingInfo(TokenBindingStatus.SUPPORTED, Optional.empty());
  }

  public Optional<ByteArray> getId() {
    return Optional.ofNullable(id);
  }
}
