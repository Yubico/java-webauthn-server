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

package com.yubico.internal.util;

import com.google.common.io.BaseEncoding;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

public class BinaryUtil {

  public static byte[] copy(byte[] bytes) {
    return Arrays.copyOf(bytes, bytes.length);
  }

  /** @param bytes Bytes to encode */
  public static String toHex(byte[] bytes) {
    return BaseEncoding.base16().encode(bytes).toLowerCase();
  }

  /** @param hex String of hexadecimal digits to decode as bytes. */
  public static byte[] fromHex(String hex) {
    return BaseEncoding.base16().decode(hex.toUpperCase());
  }

  /**
   * Parse a single byte from two hexadecimal characters.
   *
   * @param hex String of hexadecimal digits to decode as bytes.
   */
  public static byte singleFromHex(String hex) {
    ExceptionUtil.assure(
        hex.length() == 2, "Argument must be exactly 2 hexadecimal characters, was: %s", hex);
    return fromHex(hex)[0];
  }

  /**
   * Read one byte as an unsigned 8-bit integer.
   *
   * <p>Result is of type <code>short</code> because Java doesn't have unsigned types.
   *
   * @return A value between 0 and 255, inclusive.
   */
  public static short getUint8(byte b) {
    // Prepend a zero so we can parse it as a signed int16 instead of a signed int8
    return ByteBuffer.wrap(new byte[] {0, b}).order(ByteOrder.BIG_ENDIAN).getShort();
  }

  /**
   * Read 2 bytes as a big endian unsigned 16-bit integer.
   *
   * <p>Result is of type <code>int</code> because Java doesn't have unsigned types.
   *
   * @return A value between 0 and 2^16- 1, inclusive.
   */
  public static int getUint16(byte[] bytes) {
    if (bytes.length == 2) {
      // Prepend zeroes so we can parse it as a signed int32 instead of a signed int16
      return ByteBuffer.wrap(new byte[] {0, 0, bytes[0], bytes[1]})
          .order(ByteOrder.BIG_ENDIAN)
          .getInt();
    } else {
      throw new IllegalArgumentException("Argument must be 2 bytes, was: " + bytes.length);
    }
  }

  /**
   * Read 4 bytes as a big endian unsigned 32-bit integer.
   *
   * <p>Result is of type <code>long</code> because Java doesn't have unsigned types.
   *
   * @return A value between 0 and 2^32 - 1, inclusive.
   */
  public static long getUint32(byte[] bytes) {
    if (bytes.length == 4) {
      // Prepend zeroes so we can parse it as a signed int32 instead of a signed int16
      return ByteBuffer.wrap(new byte[] {0, 0, 0, 0, bytes[0], bytes[1], bytes[2], bytes[3]})
          .order(ByteOrder.BIG_ENDIAN)
          .getLong();
    } else {
      throw new IllegalArgumentException("Argument must be 4 bytes, was: " + bytes.length);
    }
  }

  public static byte[] encodeUint16(int value) {
    ExceptionUtil.assure(value >= 0, "Argument must be non-negative, was: %d", value);
    ExceptionUtil.assure(value < 65536, "Argument must be smaller than 2^16=65536, was: %d", value);

    ByteBuffer b = ByteBuffer.allocate(4);
    b.order(ByteOrder.BIG_ENDIAN);
    b.putInt(value);
    b.rewind();
    return Arrays.copyOfRange(b.array(), 2, 4);
  }

  public static byte[] encodeUint32(long value) {
    ExceptionUtil.assure(value >= 0, "Argument must be non-negative, was: %d", value);
    ExceptionUtil.assure(
        value < 4294967296L, "Argument must be smaller than 2^32=4294967296, was: %d", value);

    ByteBuffer b = ByteBuffer.allocate(8);
    b.order(ByteOrder.BIG_ENDIAN);
    b.putLong(value);
    b.rewind();
    return Arrays.copyOfRange(b.array(), 4, 8);
  }
}
