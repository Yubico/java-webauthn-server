/*
 * Copyright 2014 Yubico.
 *
 * Use of this source code is governed by a BSD-style
 * license that can be found in the LICENSE.
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

  public ByteSink putInt(int i) {
    try {
      dataOutputStream.writeInt(i);
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
    return this;
  }

  public ByteSink put(byte b) {
    try {
      dataOutputStream.write(b);
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
    return this;
  }

  public ByteSink put(byte[] b) {
    try {
      dataOutputStream.write(b);
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
    return this;
  }

  public byte[] toByteArray() {
    try {
      dataOutputStream.flush();
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
    return baos.toByteArray();
  }

  public static ByteSink create() {
    return new ByteSink();
  }
}