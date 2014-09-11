package com.google.u2f.codec;

import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.IOException;

public class ByteInputStream extends DataInputStream {

  ByteInputStream(byte[] data) {
    super(new ByteArrayInputStream(data));
  }

  byte[] read(int numberOfBytes) throws IOException {
    byte[] readBytes = new byte[numberOfBytes];
    readFully(readBytes);
    return readBytes;
  }

  byte[] readAll() throws IOException {
    byte[] readBytes = new byte[available()];
    readFully(readBytes);
    return readBytes;
  }

  byte readSigned() throws IOException {
    return readByte();
  }

  int readUnsigned() throws IOException {
    return readUnsignedByte();
  }

  boolean isExhausted() throws IOException {
    return available() == 0;
  }
}
