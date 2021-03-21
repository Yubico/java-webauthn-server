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

import static org.junit.Assert.assertEquals;

import java.util.EnumSet;
import org.junit.Test;

public class TransportTest {

  @Test
  public void testParsingSingleValuesFromInt() {
    assertEquals(EnumSet.of(Transport.BT_CLASSIC), Transport.fromInt(1));
    assertEquals(EnumSet.of(Transport.BLE), Transport.fromInt(2));
    assertEquals(EnumSet.of(Transport.USB), Transport.fromInt(4));
    assertEquals(EnumSet.of(Transport.NFC), Transport.fromInt(8));
  }

  @Test
  public void testParsingSetsFromInt() {
    assertEquals(EnumSet.noneOf(Transport.class), Transport.fromInt(0));
    assertEquals(EnumSet.of(Transport.BLE, Transport.NFC), Transport.fromInt(10));
    assertEquals(EnumSet.of(Transport.USB, Transport.BT_CLASSIC), Transport.fromInt(5));
    assertEquals(
        EnumSet.of(Transport.BT_CLASSIC, Transport.BLE, Transport.USB, Transport.NFC),
        Transport.fromInt(15));
  }

  @Test
  public void testEncodingSingleValuesToInt() {
    assertEquals(1, Transport.toInt(Transport.BT_CLASSIC));
    assertEquals(2, Transport.toInt(Transport.BLE));
    assertEquals(4, Transport.toInt(Transport.USB));
    assertEquals(8, Transport.toInt(Transport.NFC));
  }

  @Test
  public void testEncodingSetsToInt() {
    assertEquals(0, Transport.toInt());
    assertEquals(10, Transport.toInt(Transport.BLE, Transport.NFC));
    assertEquals(5, Transport.toInt(Transport.USB, Transport.BT_CLASSIC));
    assertEquals(
        15, Transport.toInt(Transport.BT_CLASSIC, Transport.BLE, Transport.USB, Transport.NFC));
  }
}
