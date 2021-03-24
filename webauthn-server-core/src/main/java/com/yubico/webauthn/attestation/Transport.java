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

package com.yubico.webauthn.attestation;

import java.util.Arrays;
import java.util.EnumSet;
import java.util.Set;

/** Representations of communication modes supported by an authenticator. */
public enum Transport {
  /** The authenticator supports communication via classic Bluetooth. */
  BT_CLASSIC(1),

  /** The authenticator supports communication via Bluetooth Low Energy (BLE). */
  BLE(2),

  /** The authenticator supports communication via USB. */
  USB(4),

  /** The authenticator supports communication via Near Field Communication (NFC). */
  NFC(8),

  /** The authenticator supports communication via Lightning. */
  LIGHTNING(16);

  private final int bitpos;

  Transport(int bitpos) {
    this.bitpos = bitpos;
  }

  public static Set<Transport> fromInt(int bits) {
    EnumSet<Transport> transports = EnumSet.noneOf(Transport.class);
    for (Transport transport : Transport.values()) {
      if ((transport.bitpos & bits) != 0) {
        transports.add(transport);
      }
    }

    return transports;
  }

  public static int toInt(Iterable<Transport> transports) {
    int transportsInt = 0;
    for (Transport transport : transports) {
      transportsInt |= transport.bitpos;
    }
    return transportsInt;
  }

  public static int toInt(Transport... transports) {
    return toInt(Arrays.asList(transports));
  }
}
