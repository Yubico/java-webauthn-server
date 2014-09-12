/*
 * Copyright 2014 Google Inc. All rights reserved.
 * Copyright 2014 Yubico.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE file or at
 * https://developers.google.com/open-source/licenses/bsd
 */

package com.yubico.u2f.codec;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;

/**
 * Provides an easy way to construct a byte array.
 */
public class ByteSink {

  ByteArrayOutputStream baos = new ByteArrayOutputStream();
  DataOutputStream dataOutputStream = new DataOutputStream(baos);

  ByteSink putInt(int i) {
    try {
      dataOutputStream.writeInt(i);
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
    return this;
  }

  ByteSink put(byte b) {
    try {
      dataOutputStream.write(b);
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
    return this;
  }

  ByteSink put(byte[] b) {
    try {
      dataOutputStream.write(b);
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
    return this;
  }

  byte[] toByteArray() {
    try {
      dataOutputStream.flush();
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
    return baos.toByteArray();
  }

  static ByteSink create() {
    return new ByteSink();
  }
}