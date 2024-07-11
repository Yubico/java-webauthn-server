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

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import lombok.AllArgsConstructor;
import lombok.NonNull;

public class BinaryUtil {

  public static byte[] copy(byte[] bytes) {
    return Arrays.copyOf(bytes, bytes.length);
  }

  /**
   * Copy <code>src</code> into <code>dest</code> beginning at the offset <code>destFrom</code>,
   * then return the modified <code>dest</code>.
   */
  public static byte[] copyInto(byte[] src, byte[] dest, int destFrom) {
    if (dest.length - destFrom < src.length) {
      throw new IllegalArgumentException("Source array will not fit in destination array");
    }
    if (destFrom < 0) {
      throw new IllegalArgumentException("Invalid destination range");
    }

    for (int i = 0; i < src.length; ++i) {
      dest[destFrom + i] = src[i];
    }

    return dest;
  }

  /** Return a new array containing the concatenation of the argument <code>arrays</code>. */
  public static byte[] concat(byte[]... arrays) {
    final int len = Arrays.stream(arrays).map(a -> a.length).reduce(0, Integer::sum);
    byte[] result = new byte[len];
    int i = 0;
    for (byte[] src : arrays) {
      copyInto(src, result, i);
      i += src.length;
    }
    return result;
  }

  /**
   * @param bytes Bytes to encode
   */
  public static String toHex(final byte[] bytes) {
    final char[] digits = new char[bytes.length * 2];
    for (int i = 0; i < bytes.length; ++i) {
      final int i2 = i * 2;
      digits[i2] = Character.forDigit((bytes[i] >> 4) & 0x0f, 16);
      digits[i2 + 1] = Character.forDigit(bytes[i] & 0x0f, 16);
    }
    return new String(digits);
  }

  /**
   * @param hex String of hexadecimal digits to decode as bytes.
   */
  public static byte[] fromHex(final String hex) {
    if (hex.length() % 2 != 0) {
      throw new IllegalArgumentException("Length of hex string is not even: " + hex);
    }

    final byte[] result = new byte[hex.length() / 2];
    for (int i = 0; i < hex.length(); ++i) {
      final int d = Character.digit(hex.charAt(i), 16);
      if (d < 0) {
        throw new IllegalArgumentException("Invalid hex digit at index " + i + " in: " + hex);
      }
      result[i / 2] |= d << (((i + 1) % 2) * 4);
    }
    return result;
  }

  /**
   * Parse a single byte from two hexadecimal characters.
   *
   * @param hex String of hexadecimal digits to decode as bytes.
   */
  public static byte singleFromHex(String hex) {
    ExceptionUtil.assertTrue(
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
    ExceptionUtil.assertTrue(value >= 0, "Argument must be non-negative, was: %d", value);
    ExceptionUtil.assertTrue(
        value < 65536, "Argument must be smaller than 2^16=65536, was: %d", value);

    ByteBuffer b = ByteBuffer.allocate(4);
    b.order(ByteOrder.BIG_ENDIAN);
    b.putInt(value);
    b.rewind();
    return Arrays.copyOfRange(b.array(), 2, 4);
  }

  public static byte[] encodeUint32(long value) {
    ExceptionUtil.assertTrue(value >= 0, "Argument must be non-negative, was: %d", value);
    ExceptionUtil.assertTrue(
        value < 4294967296L, "Argument must be smaller than 2^32=4294967296, was: %d", value);

    ByteBuffer b = ByteBuffer.allocate(8);
    b.order(ByteOrder.BIG_ENDIAN);
    b.putLong(value);
    b.rewind();
    return Arrays.copyOfRange(b.array(), 4, 8);
  }

  public static byte[] readAll(InputStream is) throws IOException {
    byte[] buffer = new byte[1024];
    int bufferLen = 0;
    while (true) {
      final int moreLen = is.read(buffer, bufferLen, buffer.length - bufferLen);
      if (moreLen <= 0) {
        return Arrays.copyOf(buffer, bufferLen);
      } else {
        bufferLen += moreLen;
        if (bufferLen == buffer.length) {
          buffer = Arrays.copyOf(buffer, buffer.length * 2);
        }
      }
    }
  }

  public static byte[] encodeDerLength(final int length) {
    if (length < 0) {
      throw new IllegalArgumentException("Length is negative: " + length);
    } else if (length <= 0x7f) {
      return new byte[] {(byte) (length & 0xff)};
    } else if (length <= 0xff) {
      return new byte[] {(byte) (0x80 | 0x01), (byte) (length & 0xff)};
    } else if (length <= 0xffff) {
      return new byte[] {
        (byte) (0x80 | 0x02), (byte) ((length >> 8) & 0xff), (byte) (length & 0xff)
      };
    } else if (length <= 0xffffff) {
      return new byte[] {
        (byte) (0x80 | 0x03),
        (byte) ((length >> 16) & 0xff),
        (byte) ((length >> 8) & 0xff),
        (byte) (length & 0xff)
      };
    } else {
      return new byte[] {
        (byte) (0x80 | 0x04),
        (byte) ((length >> 24) & 0xff),
        (byte) ((length >> 16) & 0xff),
        (byte) ((length >> 8) & 0xff),
        (byte) (length & 0xff)
      };
    }
  }

  @AllArgsConstructor
  public static class ParseDerResult<T> {
    public final T result;
    public final int nextOffset;
  }

  public static ParseDerResult<Integer> parseDerLength(@NonNull byte[] der, int offset) {
    final int len = der.length - offset;
    if (len == 0) {
      throw new IllegalArgumentException("Empty input");
    } else if ((der[offset] & 0x80) == 0) {
      return new ParseDerResult<>(der[offset] & 0xff, offset + 1);
    } else {
      final int longLen = der[offset] & 0x7f;
      if (len >= longLen) {
        switch (longLen) {
          case 0:
            throw new IllegalArgumentException(
                String.format(
                    "Empty length encoding at offset %d: 0x%s", offset, BinaryUtil.toHex(der)));
          case 1:
            return new ParseDerResult<>(der[offset + 1] & 0xff, offset + 2);
          case 2:
            return new ParseDerResult<>(
                ((der[offset + 1] & 0xff) << 8) | (der[offset + 2] & 0xff), offset + 3);
          case 3:
            return new ParseDerResult<>(
                ((der[offset + 1] & 0xff) << 16)
                    | ((der[offset + 2] & 0xff) << 8)
                    | (der[offset + 3] & 0xff),
                offset + 4);
          case 4:
            if ((der[offset + 1] & 0x80) == 0) {
              return new ParseDerResult<>(
                  ((der[offset + 1] & 0xff) << 24)
                      | ((der[offset + 2] & 0xff) << 16)
                      | ((der[offset + 3] & 0xff) << 8)
                      | (der[offset + 4] & 0xff),
                  offset + 5);
            } else {
              throw new UnsupportedOperationException(
                  String.format(
                      "Length out of range of int: 0x%02x%02x%02x%02x",
                      der[offset + 1], der[offset + 2], der[offset + 3], der[offset + 4]));
            }
          default:
            throw new UnsupportedOperationException(
                String.format("Length is too long for int: %d octets", longLen));
        }
      } else {
        throw new IllegalArgumentException(
            String.format(
                "Length encoding needs %d octets but only %s remain at index %d: 0x%s",
                longLen, len - (offset + 1), offset + 1, BinaryUtil.toHex(der)));
      }
    }
  }

  private static ParseDerResult<byte[]> parseDerTagged(
      @NonNull byte[] der, int offset, byte expectTag) {
    final int len = der.length - offset;
    if (len == 0) {
      throw new IllegalArgumentException(
          String.format("Empty input at offset %d: 0x%s", offset, BinaryUtil.toHex(der)));
    } else {
      final byte tag = der[offset];
      if (tag == expectTag) {
        final ParseDerResult<Integer> contentLen = parseDerLength(der, offset + 1);
        final int contentEnd = contentLen.nextOffset + contentLen.result;
        return new ParseDerResult<>(
            Arrays.copyOfRange(der, contentLen.nextOffset, contentEnd), contentEnd);
      } else {
        throw new IllegalArgumentException(
            String.format(
                "Incorrect tag: 0x%02x (expected 0x%02x) at offset %d: 0x%s",
                tag, expectTag, offset, BinaryUtil.toHex(der)));
      }
    }
  }

  /** Parse a SEQUENCE and return a copy of the content octets. */
  public static ParseDerResult<byte[]> parseDerSequence(@NonNull byte[] der, int offset) {
    return parseDerTagged(der, offset, (byte) 0x30);
  }

  /**
   * Parse an explicitly tagged value of class "context-specific" (bits 8-7 are 0b10), in
   * "constructed" encoding (bit 6 is 1), with a prescribed tag value, and return a copy of the
   * content octets.
   */
  public static ParseDerResult<byte[]> parseDerExplicitlyTaggedContextSpecificConstructed(
      @NonNull byte[] der, int offset, byte tagNumber) {
    if (tagNumber <= 30 && tagNumber >= 0) {
      return parseDerTagged(der, offset, (byte) ((tagNumber & 0x1f) | 0xa0));
    } else {
      throw new UnsupportedOperationException(
          String.format("Tag number out of range: %d (expected 0 to 30, inclusive)", tagNumber));
    }
  }

  public static byte[] encodeDerObjectId(@NonNull byte[] oid) {
    byte[] result = new byte[2 + oid.length];
    result[0] = 0x06;
    result[1] = (byte) oid.length;
    return BinaryUtil.copyInto(oid, result, 2);
  }

  public static byte[] encodeDerBitStringWithZeroUnused(@NonNull byte[] content) {
    return BinaryUtil.concat(
        new byte[] {0x03}, encodeDerLength(1 + content.length), new byte[] {0}, content);
  }

  public static byte[] encodeDerSequence(final byte[]... items) {
    byte[] content = BinaryUtil.concat(items);
    return BinaryUtil.concat(new byte[] {0x30}, encodeDerLength(content.length), content);
  }
}
