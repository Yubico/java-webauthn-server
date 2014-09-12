package com.google.u2f.codec;

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