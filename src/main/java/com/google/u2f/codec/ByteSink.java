package com.google.u2f.codec;

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.io.IOException;

public class ByteSink {

  ByteArrayOutputStream baos = new ByteArrayOutputStream();
  DataOutputStream w = new DataOutputStream(baos);

  ByteSink putInt(int i) {
    try {
      w.writeInt(i);
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
    return this;
  }

  ByteSink put(byte b) {
    try {
      w.write(b);
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
    return this;
  }

  ByteSink put(byte[] b) {
    try {
      w.write(b);
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
    return this;
  }

  byte[] toByteArray() {
    try {
      w.flush();
    } catch (IOException e) {
      throw new IllegalStateException(e);
    }
    return baos.toByteArray();
  }

  static ByteSink create() {
    return new ByteSink();
  }

}