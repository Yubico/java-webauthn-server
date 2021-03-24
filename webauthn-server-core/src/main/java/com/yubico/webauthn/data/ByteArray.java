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
import com.google.common.primitives.Bytes;
import com.yubico.internal.util.BinaryUtil;
import com.yubico.internal.util.json.JsonStringSerializable;
import com.yubico.internal.util.json.JsonStringSerializer;
import com.yubico.webauthn.data.exception.Base64UrlException;
import com.yubico.webauthn.data.exception.HexException;
import java.util.Base64;
import lombok.EqualsAndHashCode;
import lombok.NonNull;
import lombok.ToString;

/** An immutable byte array with support for encoding/decoding to/from various encodings. */
@JsonSerialize(using = JsonStringSerializer.class)
@EqualsAndHashCode
@ToString(includeFieldNames = false, onlyExplicitlyIncluded = true)
public final class ByteArray implements Comparable<ByteArray>, JsonStringSerializable {

  private static final Base64.Encoder BASE64_ENCODER = Base64.getEncoder();
  private static final Base64.Decoder BASE64_DECODER = Base64.getDecoder();

  private static final Base64.Encoder BASE64URL_ENCODER = Base64.getUrlEncoder().withoutPadding();
  private static final Base64.Decoder BASE64URL_DECODER = Base64.getUrlDecoder();

  @NonNull private final byte[] bytes;

  @NonNull private final String base64;

  /** Create a new instance by copying the contents of <code>bytes</code>. */
  public ByteArray(@NonNull byte[] bytes) {
    this.bytes = BinaryUtil.copy(bytes);
    this.base64 = BASE64URL_ENCODER.encodeToString(this.bytes);
  }

  private ByteArray(String base64) throws Base64UrlException {
    try {
      this.bytes = BASE64URL_DECODER.decode(base64);
    } catch (IllegalArgumentException e) {
      throw new Base64UrlException("Invalid Base64Url encoding: " + base64, e);
    }
    this.base64 = base64;
  }

  /** Create a new instance by decoding <code>base64</code> as classic Base64 data. */
  public static ByteArray fromBase64(@NonNull final String base64) {
    return new ByteArray(BASE64_DECODER.decode(base64));
  }

  /**
   * Create a new instance by decoding <code>base64</code> as Base64Url data.
   *
   * @throws Base64UrlException if <code>base64</code> is not valid Base64Url data.
   */
  @JsonCreator
  public static ByteArray fromBase64Url(@NonNull final String base64) throws Base64UrlException {
    return new ByteArray(base64);
  }

  /**
   * Create a new instance by decoding <code>hex</code> as hexadecimal data.
   *
   * @throws HexException if <code>hex</code> is not valid hexadecimal data.
   */
  public static ByteArray fromHex(@NonNull final String hex) throws HexException {
    try {
      return new ByteArray(BinaryUtil.fromHex(hex));
    } catch (Exception e) {
      throw new HexException("Invalid hexadecimal encoding: " + hex, e);
    }
  }

  /**
   * @return a new instance containing a copy of this instance followed by a copy of <code>tail
   *     </code>.
   */
  public ByteArray concat(@NonNull ByteArray tail) {
    return new ByteArray(Bytes.concat(this.bytes, tail.bytes));
  }

  public boolean isEmpty() {
    return size() == 0;
  }

  public int size() {
    return this.bytes.length;
  }

  /** @return a copy of the raw byte contents. */
  public byte[] getBytes() {
    return BinaryUtil.copy(bytes);
  }

  /** @return the content bytes encoded as classic Base64 data. */
  public String getBase64() {
    return BASE64_ENCODER.encodeToString(bytes);
  }

  /** @return the content bytes encoded as Base64Url data. */
  public String getBase64Url() {
    return base64;
  }

  /** @return the content bytes encoded as hexadecimal data. */
  @ToString.Include
  public String getHex() {
    return BinaryUtil.toHex(bytes);
  }

  /** Used by JSON serializer. */
  @Override
  public String toJsonString() {
    return base64;
  }

  @Override
  public int compareTo(ByteArray other) {
    if (bytes.length != other.bytes.length) {
      return bytes.length - other.bytes.length;
    }

    for (int i = 0; i < bytes.length; ++i) {
      if (bytes[i] != other.bytes[i]) {
        return bytes[i] - other.bytes[i];
      }
    }

    return 0;
  }
}
