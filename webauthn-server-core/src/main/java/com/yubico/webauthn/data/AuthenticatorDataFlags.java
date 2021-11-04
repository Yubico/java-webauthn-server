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
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.EqualsAndHashCode;
import lombok.ToString;

/**
 * The flags bit field of an authenticator data structure, decoded as a high-level object.
 *
 * @see <a href="https://www.w3.org/TR/2021/REC-webauthn-2-20210408/#flags">Table 1</a>
 */
@ToString
@EqualsAndHashCode
public final class AuthenticatorDataFlags {
  public final byte value;

  /** User present */
  public final boolean UP;

  /** User verified */
  public final boolean UV;

  /**
   * Attested credential data present.
   *
   * <p>Users of this library should not need to inspect this value directly.
   *
   * @see AuthenticatorData#getAttestedCredentialData()
   */
  public final boolean AT;

  /**
   * Extension data present.
   *
   * @see AuthenticatorData#getExtensions()
   */
  public final boolean ED;

  /** Decode an {@link AuthenticatorDataFlags} object from a raw bit field byte. */
  @JsonCreator
  public AuthenticatorDataFlags(@JsonProperty("value") byte value) {
    this.value = value;

    UP = (value & Bitmasks.UP) != 0;
    UV = (value & Bitmasks.UV) != 0;
    AT = (value & Bitmasks.AT) != 0;
    ED = (value & Bitmasks.ED) != 0;
  }

  private static final class Bitmasks {
    static final byte UP = 0x01;
    static final byte UV = 0x04;
    static final byte AT = 0x40;
    static final byte ED = -0x80;

    /* Reserved bits */
    // final boolean RFU1 = (value & 0x02) > 0;
    // final boolean RFU2_1 = (value & 0x08) > 0;
    // final boolean RFU2_2 = (value & 0x10) > 0;
    // static final boolean RFU2_3 = (value & 0x20) > 0;
  }
}
