/*
 * Copyright 2014 Google Inc. All rights reserved.
 * Copyright 2014 Yubico.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */

package com.yubico.u2f.codec;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;

/**
 * Provides an easy way to read a byte array in chunks.
 */
//  ByteArrayInputStream cannot throw IOExceptions, so this class is converting checked exceptions to unchecked.
public class ByteInputStream extends DataInputStream {

  ByteInputStream(byte[] data) {
    super(new ByteArrayInputStream(data));
  }

  byte[] read(int numberOfBytes) {
    byte[] readBytes = new byte[numberOfBytes];
    try {
      readFully(readBytes);
    } catch (IOException e) {
      throw new AssertionError();
    }
    return readBytes;
  }

  byte[] readAll() {
    try {
      byte[] readBytes = new byte[available()];
      readFully(readBytes);
      return readBytes;
    } catch (IOException e) {
      throw new AssertionError();
    }
  }

  int readInteger() {
    try {
      return readInt();
    } catch (IOException e) {
      throw new AssertionError();
    }
  }

  byte readSigned() {
    try {
      return readByte();
    } catch (IOException e) {
      throw new AssertionError();
    }
  }

  int readUnsigned() {
    try {
      return readUnsignedByte();
    } catch (IOException e) {
      throw new AssertionError();
    }
  }
}
