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
   * Backup eligible: the credential can and is allowed to be backed up.
   *
   * <p>NOTE that this is only a hint and not a guarantee, unless backed by a trusted authenticator
   * attestation.
   *
   * @see <a href="https://w3c.github.io/webauthn/#authdata-flags-be">§6.1. Authenticator Data</a>
   * @deprecated EXPERIMENTAL: This feature is from a not yet mature standard; it could change as
   *     the standard matures.
   */
  @Deprecated public final boolean BE;

  /**
   * Backup status: the credential is currently backed up.
   *
   * <p>NOTE that this is only a hint and not a guarantee, unless backed by a trusted authenticator
   * attestation.
   *
   * @see <a href="https://w3c.github.io/webauthn/#authdata-flags-bs">§6.1. Authenticator Data</a>
   * @deprecated EXPERIMENTAL: This feature is from a not yet mature standard; it could change as
   *     the standard matures.
   */
  @Deprecated public final boolean BS;

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
    BE = (value & Bitmasks.BE) != 0;
    BS = (value & Bitmasks.BS) != 0;
    AT = (value & Bitmasks.AT) != 0;
    ED = (value & Bitmasks.ED) != 0;

    if (BS && !BE) {
      throw new IllegalArgumentException(
          String.format("Flag combination is invalid: BE=0, BS=1 in flags: 0x%02x", value));
    }
  }

  private static final class Bitmasks {
    static final byte UP = 0x01;
    static final byte UV = 0x04;
    static final byte BE = 0x08;
    static final byte BS = 0x10;
    static final byte AT = 0x40;
    static final byte ED = -0x80;

    /* Reserved bits */
    // static final byte RFU1 = 0x02;
    // static final byte RFU2 = 0x20;
  }
}
